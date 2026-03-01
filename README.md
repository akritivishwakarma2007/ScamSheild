# ScamShield Honeypot 🛡️

**AI-Powered Scam Detection & Prevention System for India**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.9+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-orange)
![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-red)

## Overview

ScamShield Honeypot is an AI-powered proactive scam defense system designed specifically for Indian users. It detects and prevents digital scams through a hybrid approach combining rule-based pattern matching with LLM-based intent analysis.

### Problem We Solve

Digital scams in India have grown exponentially with the adoption of UPI, digital payments, and online services. From fake KYC updates to "digital arrest" threats, Indians lose crores annually to fraudsters. ScamShield provides real-time guidance and protection.

## Features

### 🔍 Hybrid Detection Engine
- **Rule-based scoring**: Keyword detection for urgency, OTP, UPI, police, refund, investment patterns
- **LLM Analysis**: Ollama-powered intent detection and psychological manipulation analysis
- **Multilingual Support**: English, Hindi, Marathi (code-mixed text supported)

### 📊 Risk Assessment
- Risk score: 0-100%
- Scam type classification (UPI Phishing, Fake Refund, Investment Scam, Loan Scam, Digital Arrest, Other)
- Clear explanation in user's detected language
- Safety guidance and warnings

### 🤖 Agentic Honeypot Mode
- For high-risk messages (≥75%), generate safe, controlled replies
- Engage with scammers without exposing real data
- Ethically gather scam patterns for learning
- Pre-filled suggested safe replies

### 🌐 Web Interface
- Clean, mobile-friendly design
- Paste suspicious messages
- Visual risk gauge with color coding
- One-click report to 1930 / cybercrime.gov.in

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI (Python) |
| LLM | Ollama (Qwen2.5:14b / Llama3.2:3b) |
| Frontend | Pure HTML + CSS + JavaScript |
| OCR (Optional) | EasyOCR + Pillow |
| Language Detection | langdetect |

## Quick Start

### Prerequisites

1. **Python 3.9+** installed
2. **Ollama** installed and running
3. Pull the required model:

```
bash
# Option 1: Qwen2.5:14b (Recommended - best for reasoning)
ollama pull qwen2.5:14b

# Option 2: Llama3.2:3b (Faster, lower memory)
ollama pull llama3.2:3b

# Option 3: Gemma2:9b (Alternative)
ollama pull gemma2:9b
```

### Installation

```
bash
# Clone or navigate to project directory
cd scamshield-web

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Copy environment file
copy .env.example .env
```

### Running the Application

```
bash
# Start Ollama (in separate terminal)
ollama serve

# Start FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Open browser
# http://localhost:8000
```

## Project Structure

```
scamshield-web/
├── README.md
├── requirements.txt
├── .env.example
├── app/
│   ├── __init__.py
│   ├── main.py           # FastAPI application
│   ├── analyzer.py       # Hybrid detection logic
│   ├── prompts.py        # LLM system prompts
│   ├── rules.py          # Rule-based scoring
│   └── utils.py          # Utility functions
├── static/
│   ├── index.html        # Main UI
│   ├── style.css         # Styling
│   └── script.js         # Frontend logic
└── .env                  # Environment variables
```

## API Endpoints

### POST /analyze
Analyze a suspicious message.

**Request:**
```
json
{
  "message": "Your OTP is 123456. UPI transaction of ₹5000 declined. Verify at suspicious-link.com"
}
```

**Response:**
```
json
{
  "risk_score": 85,
  "scam_type": "UPI Phishing",
  "explanation": "This message contains multiple red flags...",
  "high_risk": true,
  "suggested_safe_reply": "Can you send official bank email?",
  "language": "en",
  "safety_message": "Do NOT share OTP. Report to 1930"
}
```

### GET /health
Health check endpoint.

## Supported Scam Types

1. **UPI Phishing** - Fake payment requests, QR code scams
2. **Fake Refund** - False refund notifications
3. **Investment Scam** - Too-good-to-be-true returns
4. **Loan Scam** - Instant loan with processing fees
5. **Digital Arrest** - Fake police/court threats
6. **Fake KYC** - KYC update scams
7. **Other** - Miscellaneous scams

## Multilingual Support

| Language | Code | Support |
|----------|------|---------|
| English | en | Full |
| Hindi | hi | Full |
| Marathi | mr | Full |

Hindi/Marathi keywords include:
- ओटीपी (OTP)
- यूपीआई (UPI)
- पैसा (money)
- बैंक (bank)
- पुलिस (police)
- कानून (law)

## Ethical Guidelines

- 🔒 No real personal/financial data at risk
- 🔍 Anonymized learning only
- ⚠️ Clear warnings to report to authorities
- 📢 1930 / cybercrime.gov.in promoted prominently
- 🤥 Honeypot mode never reveals real user data

## Environment Variables

```
env
# .env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:14b
DEBUG=true
```

## Future Improvements

### Phase 2
- [ ] Telegram Bot Integration
- [ ] WhatsApp Business API
- [ ] Image/QR Code Analysis (EasyOCR)
- [ ] Real-time Dashboard

### Phase 3
- [ ] AWS Cloud Deployment
- [ ] Database for scam pattern storage
- [ ] Admin Panel
- [ ] SMS/Call Analysis

### Phase 4
- [ ] Browser Extension
- [ ] Mobile App
- [ ] API for third-party integrations

## Testing Messages

### English
1. "Your OTP is 847293. UPI transaction of ₹10,000 pending. Verify now to avoid debited."
2. "Congratulations! You won ₹5,00000 lottery. Click link to claim."
3. "This is SBI Bank. Your account will be blocked in 24 hours. Update KYC immediately."

### Hindi
1. "आपका OTP 123456 है। UPI से ₹5000 कट गया। वेरीफाई करें।"
2. "बधाई हो! आपने ₹10,00,000 जीते हैं। तुरंत क्लिक करें।"
3. "यह ICICI बैंक है। आपका अकाउंट 24 घंटे में बंद हो जाएगा।"

### Marathi
1. "तुमचा OTP 123456 आहे. UPI वर ₹5000 कट झाला. व्हेरिफाय करा."

## License

MIT License - Created for AI for Bharat Hackathon

## Team

**Cracked Team** - AI for Bharat Hackathon
- Team Leader: Lakshya Kumar Singh
- Members: [Your Team Members]

---

⚠️ **Disclaimer**: This is a student prototype for educational/hackathon purposes. Not for production use without proper security audits.
