"""
ScamShield Honeypot - LLM Prompts Module
=========================================
This module contains system prompts and templates for the Ollama LLM
used in scam detection and safe reply generation.

Author: Cracked Team - AI for Bharat Hackathon
Team Leader: Lakshya Kumar Singh
"""

from typing import Dict, List, Optional


# ============================================================================
# System Prompt
# ============================================================================

SYSTEM_PROMPT = """You are ScamShield, an AI-powered scam detection assistant specialized in identifying and preventing digital fraud in India. Your task is to analyze suspicious messages and provide accurate risk assessments.

## CONTEXT
- You are analyzing messages received by Indian citizens via WhatsApp, SMS, calls, or other channels
- Common scams include: UPI phishing, fake KYC, digital arrest, lottery/investment fraud, loan scams, refund tricks
- Users may send messages in English, Hindi, or Marathi (code-mixed text is common)
- Your goal is to protect users from financial fraud and psychological manipulation

## OUTPUT FORMAT (STRICT JSON)
You MUST respond with valid JSON only. No additional text.

```
json
{
  "risk_score": <number 0-100>,
  "scam_type": "<category from list below>",
  "explanation": "<2-3 sentence explanation in user's language>",
  "safe_reply": "<neutral stall reply ONLY if risk >= 75%, otherwise null>
}
```

## SCAM TYPE CATEGORIES
- "UPI Phishing" - Fake payment requests, QR code scams, UPI link fraud
- "Fake Refund" - False refund notifications, return scam
- "Investment Scam" - Too-good-to-be-true investment, crypto scams
- "Loan Scam" - Instant loan fraud, processing fee scams
- "Digital Arrest" - Fake police/court threats, blackmail
- "Fake KYC" - KYC update scams, bank verification fraud
- "Tech Support Scam" - Fake IT support, remote access fraud
- "Lottery/Prize Scam" - Fake lottery wins, prize claims
- "Other" - Miscellaneous or unknown scam type

## ANALYSIS GUIDELINES

### Risk Factors (Higher Score)
1. Requests for OTP/password/bank details
2. Threatens account suspension/blocking
3. Claims urgent action required
4. Offers unrealistic prizes/money
5. Impersonates police/bank/govt
6. Contains suspicious links/QR codes
7. Asks for payment via UPI/wire transfer

### Legitimate Indicators (Lower Score)
1. Professional formatting
2. Official contact channels
3. No urgency pressure
4. No financial requests
5. Verified sender identity

## SAFE REPLY GUIDELINES (Only for High Risk >=75%)
Generate a neutral, non-committal reply that:
- Doesn't reveal personal information
- Asks for proof/verification
- Delays/stalls the scammer
- Could be used in honeypot mode

Examples:
- English: "Can you send official bank email?" / "I'll check with my bank first"
- Hindi: "क्या आप official email भेज सकते हैं?" / "मैं बैंक से पूछ लेता हूं"
- Marathi: "तुम्ही official email पाठवू शकता?" / "मी बैंकला विचारतो"




## RESPONSE LANGUAGE
- Detect the user's language from the input message
- Respond in the SAME language as the input
- If code-mixed, use the dominant language

## FEW-SHOT EXAMPLES

Examples:
Message: "You are under digital arrest by CBI for money laundering. Join video call now or warrant issued."
→ high risk (90+), type "Digital Arrest", reply: "Please send official FIR / warrant via email from gov.in domain. I will contact local police station."

Message: "I sent ₹45000 by mistake, scan this QR to return or send back via UPI."
→ high risk (85+), type "Fake Refund", reply: "I never received any money. Please show bank statement first."

### Example 1 (High Risk - English)
Input: "Your OTP is 847293. UPI transaction of Rs 5000 pending. Verify now at suspicious-link.com or account will be blocked."
Output:
{
  "risk_score": 92,
  "scam_type": "UPI Phishing",
  "explanation": "This is a classic UPI phishing scam. The message uses urgency tactics ('account will be blocked'), requests OTP, and contains a suspicious link. Banks never ask for OTP or verification via links.",
  "safe_reply": "Can you send me the official bank email address? I'll verify through my bank's official app."
}

### Example 2 (Medium Risk - Hindi)
Input: "बधाई हो! आपने ₹10,00,000 जीते हैं। तुरंत क्लिक करके दावा करें।"
Output:
{
  "risk_score": 88,
  "scam_type": "Lottery/Prize Scam",
  "explanation": "यह लॉटरी स्कैम है। आपने किसी लॉटरी में भाग नहीं लिया होगा। Real lotteries पहले से contact करते हैं, ऐसे sudden messages नहीं आते।",
  "safe_reply": "मैंने किसी lottery में participate नहीं किया। क्या आप मुझे official documents भेज सकते हैं?"
}

### Example 3 (Low Risk - English)
Input: "Hello, your FD of Rs 1,00,000 is maturing next month. Please visit nearest branch for renewal."
Output:
{
  "risk_score": 15,
"scam_type": "Other",
"explanation": "This appears to be a legitimate bank communication about a fixed deposit maturity. No urgency, no OTP request, no suspicious links.",
  "safe_reply": null
}

### Example 4 (Digital Arrest - Hindi)
Input: "This is police. Your Aadhaar is linked to a crime case. You are under digital arrest. Transfer Rs 50,000 to secure bail or police will come to your house in 1 hour."
Output:
{
  "risk_score": 98,
  "scam_type": "Digital Arrest",
  "explanation": "यह digital arrest scam है। Police कभी money transfer नहीं मांगती। यह complete impersonation और blackmail है। Immediately report करें।",
  "safe_reply": "मैं अपने lawyer से counsel करूंगा। क्या आप official letter भेज सकते हैं?"
}

## IMPORTANT
- Always respond in valid JSON format
- If you cannot determine scam type, use "Other"
- Set risk_score to 0 if clearly legitimate
- Set risk_score to 100 if obviously scam
- safe_reply should be null for risk < 75
- Do not add any text outside the JSON
"""


# ============================================================================
# Few-Shot Examples (for reference)
# ============================================================================

FEW_SHOT_EXAMPLES = [
    {
        "input": "Your OTP is 847293. UPI transaction of Rs 5000 pending. Verify now at suspicious-link.com or account will be blocked.",
        "output": {
            "risk_score": 92,
            "scam_type": "UPI Phishing",
            "explanation": "This is a classic UPI phishing scam using urgency tactics and requesting OTP.",
            "safe_reply": "Can you send me the official bank email address?"
        }
    },
    {
        "input": "बधाई हो! आपने ₹10,00,000 जीते हैं। तुरंत क्लिक करके दावा करें।",
        "output": {
            "risk_score": 88,
            "scam_type": "Lottery/Prize Scam",
            "explanation": "यह लॉटरी स्कैम है। Real lotteries पहले से contact करते हैं।",
            "safe_reply": "मैंने किसी lottery में participate नहीं किया।"
        }
    }
]


# ============================================================================
# Prompt Templates
# ============================================================================

def build_analysis_prompt(message: str) -> str:
    """
    Build the prompt for LLM analysis.
    
    Args:
        message: The suspicious message to analyze
        
    Returns:
        Complete prompt string for the LLM
    """
    return f"""{SYSTEM_PROMPT}

Now analyze this message:

---
{message}
---

Respond with valid JSON only."""


def build_safe_reply_prompt(
    message: str,
    scam_type: str,
    language: str
) -> str:
    """
    Build a prompt specifically for generating safe replies.
    
    Args:
        message: The original suspicious message
        scam_type: Detected scam type
        language: Language code (en, hi, mr)
        
    Returns:
        Prompt for safe reply generation
    """
    language_instructions = {
        "en": "Respond in English.",
        "hi": "Respond in Hindi (use Devanagari script).",
        "mr": "Respond in Marathi (use Devanagari script)."
    }
    
    return f"""Generate a safe, neutral reply to stall a scammer. The message was classified as: {scam_type}

Requirements:
- Don't reveal any personal information
- Ask for verification/proof
- Delay the conversation
- Keep it short (1-2 sentences)
- {language_instructions.get(language, language_instructions['en'])}

Examples:
- "Can you send official documents?"
- "I'll verify with my bank first."
- "Let me check with my family."

Generate only the reply text, no JSON needed."""


# ============================================================================
# Response Parsing
# ============================================================================

def parse_llm_response(response: str) -> Optional[Dict]:
    """
    Parse the LLM JSON response.
    
    Args:
        response: Raw response from LLM
        
    Returns:
        Parsed dictionary or None if parsing fails
    """
    import json
    import re
    
    # Try to extract JSON from response
    # Sometimes LLM adds text before/after JSON
    
    # Find JSON block
    json_match = re.search(r'\{[\s\S]*\}', response)
    
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    
    # Try parsing entire response
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        return None


# ============================================================================
# Validation
# ============================================================================

def validate_response(response: Dict) -> bool:
    """
    Validate that the LLM response has all required fields.
    
    Args:
        response: Parsed LLM response
        
    Returns:
        True if valid, False otherwise
    """
    required_fields = ["risk_score", "scam_type", "explanation"]
    
    for field in required_fields:
        if field not in response:
            return False
    
    # Validate risk_score range
    if not isinstance(response["risk_score"], (int, float)):
        return False
    if response["risk_score"] < 0 or response["risk_score"] > 100:
        return False
    
    # Validate scam_type
    valid_types = [
        "UPI Phishing",
        "Fake Refund",
        "Investment Scam",
        "Loan Scam",
        "Digital Arrest",
        "Fake KYC",
        "Tech Support Scam",
        "Lottery/Prize Scam",
        "Other"
    ]
    
    if response["scam_type"] not in valid_types:
        return False
    
    return True


# ============================================================================
# Default Response (fallback)
# ============================================================================

def get_default_response() -> Dict:
    """
    Get default response when LLM fails.
    
    Returns:
        Default error response
    """
    return {
        "risk_score": 50,
        "scam_type": "Other",
        "explanation": "Unable to analyze message. Please be cautious and verify through official channels.",
        "safe_reply": None
    }
