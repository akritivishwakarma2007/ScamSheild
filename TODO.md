
# ScamShield Detection Accuracy Improvement - TODO

## Tasks:
- [x] 1. Enhanced rule-based detection with more comprehensive patterns
- [x] 2. URL/phone number deep analysis
- [x] 3. Better language detection for code-mixed text
- [x] 4. Honeypot chat endpoint for engaging with scammers

## Implementation Order:
1. ✅ Enhance `app/rules.py` - Add comprehensive keyword patterns and deep analysis
2. ✅ Add `POST /chat` endpoint in `app/main.py` - Honeypot chat for interacting with scammers
3. ✅ Add session management for honeypot in `app/main.py`
4. ✅ Add information extraction (UPI ID, phone, bank, amount) in `app/main.py`
