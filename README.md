# API Abuse Detection Platform

A cloud-native middleware gateway that detects and prevents bot-based API abuse in real time using a 7-signal behavioural scoring engine — deployed on AWS.

Built to solve the real-world problem of bots buying tickets on platforms like BookMyShow before real users get a chance.

---

## Live Demo

🔴 **Live Dashboard:** https://api-abuse-dashboard.s3.ap-southeast-2.amazonaws.com/dashboard_live.html

> Simulates a Coldplay concert ticket booking system.
> Normal users book freely. Bots get detected and blocked within 2 requests.

![Architecture](https://img.shields.io/badge/AWS-Lambda%20%7C%20DynamoDB%20%7C%20API%20Gateway%20%7C%20SNS-orange)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![Status](https://img.shields.io/badge/Status-Live-brightgreen)

---

## The Problem

Every time a popular event goes on sale, bots exploit the booking API directly — bypassing the app, sending thousands of requests per second, and buying all tickets before real users can. Traditional rate limiting only blocks after damage is done.

This system detects bot behaviour **before** a single ticket is wrongly sold.

---

## Architecture

```
User / Bot
    │
    ▼
API Gateway (REST)
    │
    ▼
AWS Lambda — apiAbuseDetector
    │
    ├── DynamoDB — apiUsageDB      (per-key behaviour history)
    ├── DynamoDB — blocklist       (permanently blocked keys)
    ├── DynamoDB — ipUsageDB       (per-IP tracking)
    │
    ├── SNS — api-abuse-alerts     (email on block)
    │
    └── External API               (forwarded only if ALLOWED)
```

---

## Detection Engine — 7 Signals

Every incoming request is scored 0–100 across 7 independent signals:

| Signal | Max Score | What it detects |
|---|---|---|
| Burst rate | 40 | Requests faster than 2 seconds apart |
| Timing regularity | 20 | Perfectly consistent intervals (machine-like) |
| IP key count | 25 | Multiple API keys from the same IP (key rotation) |
| IP volume | 20 | More than 50 requests/min from one IP |
| Payload fingerprinting | 25 | Identical repeated request bodies |
| User-Agent analysis | 25 | Python, curl, wget, headless scripts |
| ML anomaly (Z-score) | 20 | Statistical deviation from behavioural baseline |

### Decision Thresholds

| Score | Decision | Action |
|---|---|---|
| 0 – 49 | ALLOWED | Request forwarded to real API |
| 50 – 79 | THROTTLED | Request slowed down |
| 80 – 100 | BLOCKED | Key permanently banned + email alert |

### Score Decay

Legitimate users recover automatically. Waiting 30+ seconds decays the score by 90%, so a human who accidentally triggered suspicion is forgiven immediately.

---

## ML Anomaly Detection

The 7th signal uses **Z-score statistical anomaly detection** — a technique from unsupervised machine learning.

After collecting 6+ request intervals for a key, the system builds a statistical baseline of that key's normal behaviour. If a new request deviates more than 2 standard deviations from that baseline, it is flagged as anomalous.

This catches **low-and-slow bots** that randomise their timing to evade rule-based detection — directly addressing the limitation of pure timing-based systems.

```python
z_score = abs((current_diff - mean) / stdev)

if   z_score > 4: anomaly_score = 20  # extreme outlier
elif z_score > 3: anomaly_score = 12  # strong outlier
elif z_score > 2: anomaly_score = 6   # moderate outlier
```

---

## AWS Services Used

| Service | Purpose |
|---|---|
| API Gateway | Receives all incoming requests |
| Lambda (Python 3.11) | Runs detection engine in real time |
| DynamoDB | Stores per-key and per-IP behaviour history |
| SNS | Sends email alert when a key is blocked |

---

## Dashboard

A real-time web dashboard shows:

- Live request stats (allowed / throttled / blocked)
- Per-request abuse score with signal breakdown
- Request decision timeline chart
- IP threat tracker with threat level (LOW / MED / HIGH)
- Ticket counter showing bots blocked vs real sales
- Full request log with all 7 signal scores

---

## Getting Started

### Prerequisites

- AWS account with Lambda, DynamoDB, API Gateway, SNS configured
- Python 3.x for local server

### DynamoDB Tables Required

Create these 3 tables in AWS DynamoDB:

| Table | Partition Key |
|---|---|
| `apiUsageDB` | `api_key` (String) |
| `blocklist` | `api_key` (String) |
| `ipUsageDB` | `ip` (String) |

### Deploy Lambda

1. Create Lambda function `apiAbuseDetector` (Python 3.11)
2. Paste code from `lambda_function.py`
3. Set timeout to 10 seconds
4. Attach `AmazonDynamoDBFullAccess` and `AmazonSNSFullAccess` policies

### Configure API Gateway

1. Create HTTP API
2. Add route: `POST /checkRequest`
3. Integrate with `apiAbuseDetector` Lambda
4. Add route: `OPTIONS /checkRequest` (same Lambda)
5. Set CORS: Allow origin `*`, headers `*`, methods `*`
6. Deploy to stage `prod`

### Run Dashboard Locally

```bash
cd project-folder
python -m http.server 8080
```

Open `http://localhost:8080/dashboard_live.html`

---

## Demo Scenarios

### Scenario 1 — Normal user
1. Enter API key `user-alice`
2. Click **Book Ticket** every 10 seconds
3. Every request → ALLOWED, tickets decrease normally

### Scenario 2 — Bot attack
1. Set bot intensity to 50, key rotation to 5
2. Click **Bot Attack**
3. Bot gets BLOCKED within 2 requests
4. Tickets remain protected
5. Email alert arrives at configured SNS email

### Scenario 3 — Slow random bot (ML detection)
1. Use Lambda test with same API key, 8 times
2. After 6 requests the ML anomaly signal activates
3. Score increases even without rapid firing

---

## Key Advantages Over Existing Solutions

| Feature | This System | Traditional WAF |
|---|---|---|
| Cost | Near zero (AWS free tier) | $100s/month |
| Transparency | Full signal breakdown | Black box |
| Detection type | Behaviour-based | Rule-based |
| ML anomaly detection | Yes (Z-score) | Rarely |
| Setup time | Minutes | Days |
| Payload analysis | Yes | No |

---

## Known Limitations

- Headless browser bots (Selenium, Puppeteer) evade User-Agent detection
- Highly distributed botnet attacks (thousands of IPs) evade IP signals
- Next steps: device fingerprinting, CAPTCHA integration, IP reputation databases

---

## Project Structure

```
api-abuse-detection-platform/
├── lambda_function.py      # Main detection engine (7 signals)
├── dashboard_live.html     # Real-time dashboard (AWS connected)
├── dashboard_demo.html     # Offline demo dashboard
└── README.md
```

---

## Author

**Anvay** — [@anvay-anyway](https://github.com/anvay-anyway)

Built as a college hackathon project. Demonstrates cloud-native API security using AWS serverless architecture and multi-signal behavioural detection.

---

## Tags

`aws` `lambda` `dynamodb` `api-security` `bot-detection` `anomaly-detection` `cloud-native` `serverless` `python` `cybersecurity`
