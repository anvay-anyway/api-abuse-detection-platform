import json
import boto3
import time
import urllib.request

# AWS Clients
dynamodb = boto3.resource('dynamodb', region_name='ap-southeast-2')
sns = boto3.client('sns', region_name='ap-southeast-2')

# Tables
table = dynamodb.Table('apiUsageDB')
blocklist = dynamodb.Table('blocklist')

# SNS Topic ARN
SNS_TOPIC_ARN = 'arn:aws:sns:ap-southeast-2:120221303204:api-abuse-alerts'


def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body', '{}'))

        api_key = body.get('api_key', 'unknown')
        target_url = body.get('target_url', 'https://jsonplaceholder.typicode.com/todos/1')

        now = int(time.time())

        # Check blocklist
        blocked = blocklist.get_item(Key={'api_key': api_key})
        if blocked.get('Item'):
            return {
                "statusCode": 403,
                "headers": {"Access-Control-Allow-Origin": "*"},
                "body": json.dumps({
                    "decision": "BLOCKED",
                    "message": "You are permanently blocked."
                })
            }

        # Fetch existing data
        response = table.get_item(Key={'api_key': api_key})
        item = response.get('Item', None)

        if item is None:
            request_count = 1
            abuse_score = 0
            last_request = now
        else:
            request_count = int(item.get('request_count', 0)) + 1
            last_request = int(item.get('last_request', now))
            abuse_score = int(item.get('abuse_score', 0))

            time_diff = now - last_request

            if time_diff < 5:
                abuse_score += 20
            elif time_diff < 30:
                abuse_score += 10
            else:
                abuse_score = max(0, abuse_score - 5)

            if request_count % 3 == 0:
                abuse_score += 5

        abuse_score = min(abuse_score, 100)

        # Decision logic
        if abuse_score > 70:
            decision = "BLOCKED"

            blocklist.put_item(Item={
                'api_key': api_key,
                'blocked_at': now,
                'reason': 'Abuse score exceeded 70'
            })

            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=f"API Key {api_key} blocked. Score: {abuse_score}",
                Subject='API Abuse Alert'
            )

        elif abuse_score > 30:
            decision = "THROTTLED"
        else:
            decision = "ALLOWED"

        # Save state
        table.put_item(Item={
            'api_key': api_key,
            'request_count': request_count,
            'last_request': now,
            'abuse_score': abuse_score,
            'decision': decision
        })

        # Forward request if allowed
        if decision == "ALLOWED":
            with urllib.request.urlopen(target_url) as response:
                api_response = json.loads(response.read().decode())

            return {
                "statusCode": 200,
                "headers": {"Access-Control-Allow-Origin": "*"},
                "body": json.dumps({
                    "gateway_decision": decision,
                    "target_url": target_url,
                    "api_response": api_response
                })
            }

        elif decision == "THROTTLED":
            return {
                "statusCode": 429,
                "headers": {"Access-Control-Allow-Origin": "*"},
                "body": json.dumps({
                    "decision": decision,
                    "message": "Too many requests. Slow down."
                })
            }

        else:
            return {
                "statusCode": 403,
                "headers": {"Access-Control-Allow-Origin": "*"},
                "body": json.dumps({
                    "decision": decision,
                    "message": "Blocked due to abuse."
                })
            }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"error": str(e)})
        }
