import json
import boto3
import time
import math
import hashlib
import statistics
import urllib.request

dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2')
sns      = boto3.client('sns',      region_name='ap-southeast-2')

table         = dynamodb.Table('apiUsageDB')
blocklist_tbl = dynamodb.Table('blocklist')
ip_table      = dynamodb.Table('ipUsageDB')

SNS_TOPIC_ARN = 'arn:aws:sns:ap-southeast-2:120221303204:api-abuse-alerts'

BLOCK_THRESHOLD    = 80
THROTTLE_THRESHOLD = 50
DECAY_RATE         = 0.6


def lambda_handler(event, context):

    if event.get('httpMethod') == 'OPTIONS' or \
       event.get('requestContext', {}).get('http', {}).get('method') == 'OPTIONS':
        return _resp(200, {})

    try:
        body       = json.loads(event.get('body', '{}'))
        api_key    = body.get('api_key', 'unknown')
        target_url = body.get('target_url', 'https://jsonplaceholder.typicode.com/todos/1')
        now        = int(time.time())
        client_ip  = get_client_ip(event)
        headers    = event.get('headers', {}) or {}

        # ── 1. Blocklist check ───────────────────────────────
        blocked = blocklist_tbl.get_item(Key={'api_key': api_key})
        if blocked.get('Item'):
            return _resp(403, {
                "decision": "BLOCKED",
                "reason": "permanently_blocked",
                "message": "This API key is permanently blocked.",
                "abuse_score": 100,
                "ip": client_ip,
                "signals": {"burst_score": 0, "regularity_score": 0,
                            "ip_key_score": 0, "ip_volume_score": 0,
                            "payload_score": 0, "ua_score": 0,
                            "ml_anomaly_score": 0}
            })

        # ── 2. Load existing record ──────────────────────────
        resp           = table.get_item(Key={'api_key': api_key})
        item           = resp.get('Item', {})
        request_count  = int(item.get('request_count', 0)) + 1
        last_request   = int(item.get('last_request', now))
        stored_score   = float(item.get('abuse_score', 0))
        intervals      = list(item.get('intervals', []))
        payload_hashes = list(item.get('payload_hashes', []))
        time_diff      = max(now - last_request, 0)

        # ── 3. Decay first ───────────────────────────────────
        if item:
            if time_diff > 30:
                stored_score = stored_score * 0.1
            elif time_diff > 15:
                stored_score = stored_score * 0.3
            elif time_diff > 10:
                stored_score = stored_score * 0.5
            elif time_diff > 5:
                stored_score = stored_score * 0.8

        # ── 4. Burst signal ──────────────────────────────────
        if   time_diff < 1:  burst_score = 40
        elif time_diff < 2:  burst_score = 25
        elif time_diff < 5:  burst_score = 10
        elif time_diff < 15: burst_score = 3
        else:                burst_score = 0

        # ── 5. Regularity signal ─────────────────────────────
        if item:
            intervals.append(time_diff)
            intervals = intervals[-10:]
        regularity_score = compute_regularity(intervals)

        # ── 6. IP signals ────────────────────────────────────
        ip_key_score, ip_volume_score = compute_ip_signals(client_ip, api_key, now)

        # ── 7. Payload fingerprinting ────────────────────────
        payload_hash = hashlib.md5(
            json.dumps(body, sort_keys=True).encode()
        ).hexdigest()
        repeat_count = payload_hashes.count(payload_hash)
        if   repeat_count >= 5: payload_score = 25
        elif repeat_count >= 3: payload_score = 15
        elif repeat_count >= 1: payload_score = 5
        else:                   payload_score = 0
        payload_hashes.append(payload_hash)
        payload_hashes = payload_hashes[-15:]

        # ── 8. User-Agent analysis ───────────────────────────
        user_agent = headers.get('user-agent', '').lower()
        if not user_agent:
            ua_score = 20
        elif any(x in user_agent for x in ['python', 'curl', 'wget', 'java', 'bot', 'crawler', 'requests']):
            ua_score = 25
        elif any(x in user_agent for x in ['mozilla', 'chrome', 'safari', 'firefox']):
            ua_score = 0
        else:
            ua_score = 8

        # ── 9. ML Anomaly Detection (Z-score based) ──────────
        # Uses statistical anomaly detection on request intervals.
        # If current behaviour deviates significantly from this
        # key's historical baseline, it is flagged as anomalous.
        # This catches slow random bots that evade timing rules.
        ml_anomaly_score = compute_ml_anomaly(time_diff, intervals)

        # ── 10. Final score ──────────────────────────────────
        delta = (burst_score + regularity_score + ip_key_score +
                 ip_volume_score + payload_score + ua_score +
                 ml_anomaly_score)
        new_score = min(100, stored_score + delta)

        # ── 11. Decision ─────────────────────────────────────
        if   new_score >= BLOCK_THRESHOLD:    decision = "BLOCKED"
        elif new_score >= THROTTLE_THRESHOLD: decision = "THROTTLED"
        else:                                 decision = "ALLOWED"

        # ── 12. Save to DynamoDB ─────────────────────────────
        table.put_item(Item={
            'api_key':        api_key,
            'request_count':  request_count,
            'last_request':   now,
            'abuse_score':    int(new_score),
            'decision':       decision,
            'client_ip':      client_ip,
            'intervals':      intervals,
            'payload_hashes': payload_hashes,
        })

        # ── 13. Block + SNS alert ────────────────────────────
        if decision == "BLOCKED" and item.get('decision') != "BLOCKED":
            blocklist_tbl.put_item(Item={
                'api_key':    api_key,
                'blocked_at': now,
                'ip':         client_ip,
                'reason':     (
                    f'Score {int(new_score)}/100 — '
                    f'burst={burst_score} reg={regularity_score} '
                    f'ipk={ip_key_score} ipv={ip_volume_score} '
                    f'payload={payload_score} ua={ua_score} '
                    f'ml={ml_anomaly_score}'
                ),
            })
            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject='API Abuse Alert - Key Blocked',
                    Message=(
                        f"API Key blocked: {api_key}\n"
                        f"IP Address: {client_ip}\n"
                        f"Abuse Score: {int(new_score)}/100\n"
                        f"Total Requests: {request_count}\n\n"
                        f"Signal Breakdown:\n"
                        f"  Burst rate       : {burst_score}\n"
                        f"  Regularity       : {regularity_score}\n"
                        f"  IP key count     : {ip_key_score}\n"
                        f"  IP volume        : {ip_volume_score}\n"
                        f"  Payload repeat   : {payload_score}\n"
                        f"  User-Agent       : {ua_score}\n"
                        f"  ML anomaly score : {ml_anomaly_score}\n\n"
                        f"User-Agent: {user_agent or 'none'}\n"
                        f"-- API Abuse Detection System"
                    )
                )
            except Exception as e:
                print(f"SNS error: {e}")

        # ── 14. Response ─────────────────────────────────────
        signals = {
            "burst_score":      burst_score,
            "regularity_score": regularity_score,
            "ip_key_score":     ip_key_score,
            "ip_volume_score":  ip_volume_score,
            "payload_score":    payload_score,
            "ua_score":         ua_score,
            "ml_anomaly_score": ml_anomaly_score,
        }
        meta = {
            "decision":      decision,
            "abuse_score":   int(new_score),
            "request_count": request_count,
            "ip":            client_ip,
            "signals":       signals,
        }

        if decision == "ALLOWED":
            try:
                with urllib.request.urlopen(target_url, timeout=5) as r:
                    api_response = json.loads(r.read().decode())
            except Exception as e:
                api_response = {"note": "external API unavailable", "error": str(e)}
            return _resp(200, {"gateway_decision": decision,
                               "api_response": api_response, **meta})

        if decision == "THROTTLED":
            return _resp(429, {"message": "Too many requests. Slow down.", **meta})

        return _resp(403, {"message": "Blocked due to abuse.", **meta})

    except Exception as e:
        return _resp(500, {"error": str(e)})


# ── SIGNAL FUNCTIONS ──────────────────────────────────────────

def compute_regularity(intervals):
    """Detects bots firing at perfectly consistent intervals."""
    if len(intervals) < 5:
        return 0
    mean = sum(intervals) / len(intervals)
    if mean == 0:
        return 15
    std = math.sqrt(sum((x - mean) ** 2 for x in intervals) / len(intervals))
    cv  = std / mean
    if   cv < 0.05: return 20
    elif cv < 0.10: return 12
    elif cv < 0.20: return 5
    return 0


def compute_ml_anomaly(current_diff, intervals):
    """
    Z-score based statistical anomaly detection.

    Builds a baseline of normal request intervals for this API key.
    If the current request's timing deviates more than 2 standard
    deviations from that baseline, it is statistically anomalous.

    This catches slow random bots — even if they randomise their
    timing, their overall distribution will differ from real human
    behaviour once enough data is collected.

    Needs at least 6 intervals to activate (avoids false positives
    on new keys with no history).
    """
    if len(intervals) < 6:
        return 0   # not enough history yet

    try:
        mean   = statistics.mean(intervals)
        stdev  = statistics.stdev(intervals)

        if stdev == 0:
            # Perfect consistency = extremely suspicious
            return 20

        z_score = abs((current_diff - mean) / stdev)

        # Z-score > 3 means current behaviour is extremely unusual
        # compared to this key's own history
        if   z_score > 4:  return 20   # extreme outlier
        elif z_score > 3:  return 12   # strong outlier
        elif z_score > 2:  return 6    # moderate outlier
        return 0                        # within normal range

    except Exception:
        return 0


def compute_ip_signals(ip, api_key, now):
    """Detects key rotation and high volume from one IP."""
    if ip == 'unknown':
        return 0, 0
    try:
        resp      = ip_table.get_item(Key={'ip': ip})
        item      = resp.get('Item', {})
        seen_keys = set(item.get('seen_keys', []))
        seen_keys.add(api_key)
        timestamps = [t for t in item.get('recent_timestamps', []) if t > now - 60]
        timestamps.append(now)
        ip_table.put_item(Item={
            'ip':                ip,
            'seen_keys':         list(seen_keys),
            'recent_timestamps': timestamps,
            'last_seen':         now,
        })
        key_count = len(seen_keys)
        req_count = len(timestamps)
        if   key_count >= 10: ip_key_score = 25
        elif key_count >= 5:  ip_key_score = 15
        elif key_count >= 3:  ip_key_score = 5
        else:                 ip_key_score = 0
        if   req_count >= 50: ip_volume_score = 20
        elif req_count >= 30: ip_volume_score = 12
        elif req_count >= 15: ip_volume_score = 5
        else:                 ip_volume_score = 0
        return ip_key_score, ip_volume_score
    except Exception:
        return 0, 0


def get_client_ip(event):
    rc = event.get('requestContext', {})
    ip = rc.get('identity', {}).get('sourceIp')
    if ip: return ip
    ip = rc.get('http', {}).get('sourceIp')
    if ip: return ip
    forwarded = (event.get('headers', {}) or {}).get('X-Forwarded-For', '')
    if forwarded: return forwarded.split(',')[0].strip()
    return 'unknown'


def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Access-Control-Allow-Origin":      "*",
            "Access-Control-Allow-Headers":     "*",
            "Access-Control-Allow-Methods":     "POST, OPTIONS, GET",
            "Access-Control-Allow-Credentials": "false",
        },
        "body": json.dumps(body),
    }
