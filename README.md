# 🚀 Cloud-Native API Abuse Detection Platform

## 📌 Overview
This project is a cloud-native API security gateway that detects and prevents API abuse in real-time using behavior-based scoring.

It dynamically classifies incoming requests as:
- ✅ ALLOWED
- ⚠️ THROTTLED
- ❌ BLOCKED

---

## 🧠 Key Features
- Real-time API abuse detection
- Behavior-based scoring system
- Automatic blocking using blocklist
- Email alerts using AWS SNS
- Dynamic API routing (supports any backend API)
- Cloud-hosted dashboard (AWS S3)

---

## 🏗️ Architecture

Client → API Gateway → AWS Lambda → DynamoDB  
                             ↓  
                     Decision Engine  
                             ↓  
                     Forward to API  

---

## ⚙️ Tech Stack
- AWS Lambda (Python)
- API Gateway
- DynamoDB
- Amazon SNS
- S3 (Frontend hosting)
- HTML/CSS/JavaScript

---

## 🧪 Demo Flow
1. Send request → Allowed
2. Burst requests → Throttled
3. Continuous abuse → Blocked
4. Email alert triggered
5. API calls blocked from reaching backend

---

## 🔥 Unique Point
Unlike traditional rate limiting, this system uses **behavior-based adaptive scoring** to detect abuse dynamically.

---

## ⚠️ Limitations
- Does not handle distributed attacks
- No IP-based tracking yet
- No ML-based anomaly detection

---

## 🚀 Future Improvements
- IP-based tracking
- Machine learning detection
- Multi-endpoint protection

---

## 👨‍💻 Author
Anvay Gaikwad
