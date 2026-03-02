"""
ScamShield Honeypot - Hybrid Analyzer Module
=============================================
This module combines rule-based scoring with LLM analysis
to provide accurate scam detection.

Author: Cracked Team - AI for Bharat Hackathon
Team Leader: Lakshya Kumar Singh
"""
"""
ScamShield Honeypot - Hybrid Analyzer Module
=============================================
This module combines rule-based scoring with LLM analysis
to provide accurate scam detection.

Author: Cracked Team - AI for Bharat Hackathon
Team Leader: Lakshya Kumar Singh
"""

import os
import json
import logging
from typing import Dict, Optional, Tuple
import asyncio

from app.rules import rule_based_score, get_explanation
from app.prompts import (
    build_analysis_prompt,
    parse_llm_response,
    validate_response,
    get_default_response,
    SYSTEM_PROMPT
)

# Configure logging
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

# Weights for hybrid scoring
RULE_WEIGHT = 0.40  # 40% for rule-based
LLM_WEIGHT = 0.60   # 60% for LLM

# Risk threshold for high risk
HIGH_RISK_THRESHOLD = 75

# Timeout for LLM requests (seconds)
LLM_TIMEOUT = 60

# Bedrock client (global, initialized once)
bedrock = boto3.client('bedrock-runtime', region_name='ap-south-1')  # Mumbai region for low latency

# ============================================================================
# LLM Analysis Functions
# ============================================================================

def call_bedrock(message: str) -> Dict:
    """
    Call Amazon Bedrock (Claude 3.5 Sonnet) for LLM analysis.
    
    Args:
        message: The suspicious message to analyze
        
    Returns:
        Dictionary with LLM analysis results
    """
    model_id = "anthropic.claude-3-5-sonnet-20241022-v2:0"  # Claude 3.5 Sonnet v2 (2024-10-22)

    prompt = build_analysis_prompt(message)

    # Claude uses messages format
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 500,
        "temperature": 0.1,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    })

    logger.info(f"🤖 Calling Bedrock with model: {model_id}")

    try:
        response = bedrock.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=body
        )

        response_body = json.loads(response['body'].read())
        llm_response = response_body['content'][0]['text'].strip()  # Claude returns text in content[0]

        parsed = parse_llm_response(llm_response)

        if parsed and validate_response(parsed):
            logger.info(f"✅ Bedrock analysis successful: {parsed.get('risk_score', 0)}%")
            return parsed
        else:
            logger.warning("⚠️ Bedrock response parsing failed, using default")
            return get_default_response()

    except Exception as e:
        logger.error(f"❌ Bedrock error: {str(e)}")
        return get_default_response()


async def call_ollama(message: str) -> Dict:
    """
    Legacy Ollama call – kept as fallback or local dev option
    """
    import ollama
    
    model = os.getenv("OLLAMA_MODEL", "gemma2:2b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))
    
    prompt = build_analysis_prompt(message)
    
    logger.info(f"🤖 Calling Ollama fallback with model: {model}")
    
    try:
        response = await asyncio.to_thread(
            ollama.generate,
            model=model,
            prompt=prompt,
            format="json",
            options={
                "temperature": temperature,
                "num_predict": 500,
                "stop": ["```", "```json", "\n\n"],
            }
        )
        
        llm_response = response.get("response", "")
        parsed = parse_llm_response(llm_response)
        
        if parsed and validate_response(parsed):
            logger.info(f"✅ Ollama fallback successful: {parsed.get('risk_score', 0)}%")
            return parsed
        else:
            return get_default_response()
            
    except Exception as e:
        logger.error(f"❌ Ollama fallback error: {str(e)}")
        return get_default_response()


def call_ollama_sync(message: str) -> Dict:
    """
    Synchronous Ollama fallback
    """
    # ... (your existing code remains, but you can simplify or remove if Bedrock is primary)
    # For brevity – call the async version or keep as-is
    return asyncio.run(call_ollama(message))  # simple sync wrapper


# ============================================================================
# Hybrid Analysis (updated to prefer Bedrock)
# ============================================================================

async def analyze_message(message: str) -> Dict:
    """
    Perform hybrid analysis – now prefers Bedrock, falls back to Ollama if needed
    """
    logger.info("🔍 Starting hybrid analysis...")

    # Rule-based
    logger.info("📋 Running rule-based analysis...")
    rule_result = rule_based_score(message)
    rule_score = rule_result.score
    language = rule_result.detected_language
    logger.info(f"Rule score: {rule_score}% ({', '.join(rule_result.matched_categories)})")

    # LLM – try Bedrock first
    logger.info("🤖 Running LLM analysis (Bedrock preferred)...")
    llm_result = call_bedrock(message)
    
    # If Bedrock fails badly (e.g. access denied), fallback to Ollama
    if llm_result == get_default_response():
        logger.warning("Bedrock returned default – falling back to Ollama")
        llm_result = call_ollama_sync(message)

    llm_score = llm_result.get("risk_score", 50)
    logger.info(f"LLM score: {llm_score}%")

    # Combine scores
    final_score = int((rule_score * RULE_WEIGHT) + (llm_score * LLM_WEIGHT))
    final_score = min(max(final_score, 0), 100)

    logger.info(f"Final score: {final_score}%")

    # Scam type (prefer LLM)
    scam_type = llm_result.get("scam_type", "Other")

    # Explanation (prefer LLM)
    explanation = llm_result.get("explanation") or get_explanation(rule_result.matched_categories, language)

    is_high_risk = final_score >= HIGH_RISK_THRESHOLD

    safe_reply = None
    if is_high_risk:
        safe_reply = llm_result.get("safe_reply") or generate_default_safe_reply(language, scam_type)

    safety_message = generate_safety_message(language)

    result = {
        "risk_score": final_score,
        "scam_type": scam_type,
        "explanation": explanation,
        "high_risk": is_high_risk,
        "suggested_safe_reply": safe_reply,
        "language": language,
        "safety_message": safety_message,
        "_debug": {
            "rule_score": rule_score,
            "llm_score": llm_score,
            "rule_categories": rule_result.matched_categories,
            "llm_source": "bedrock" if "Bedrock" in llm_result.get("_debug", {}).get("source", "") else "ollama"
        }
    }

    logger.info(f"✅ Analysis complete: {final_score}% - {scam_type}")
    return result


def generate_default_safe_reply(language: str, scam_type: str) -> str:
    """
    Generate a default safe reply based on language and scam type.
    
    Args:
        language: Language code
        scam_type: Type of scam detected
        
    Returns:
        Safe reply string
    """
    replies = {
        "en": {
            "default": "Can you send me official documents? I'll verify with my bank first.",
            "upi": "I'll check my UPI app directly. Can you share official bank email?",
            "digital_arrest": "I need to consult my lawyer first. Can you send official documents?",
            "loan": "Let me check my credit score first. What is your official website?",
            "prize": "I didn't participate in any lottery. Can you send official documents?"
        },
        "hi": {
            "default": "क्या आप official documents भेज सकते हैं? मैं बैंक से पूछ लेता हूं।",
            "upi": "मैं अपने UPI app में check करूंगा। क्या आप official bank email भेज सकते हैं?",
            "digital_arrest": "मुझे अपने वकील से consult करना है। क्या आप official documents भेज सकते हैं?",
            "loan": "मैं अपना credit score check करूंगा। आपकी official website क्या है?",
            "prize": "मैंने किसी lottery में participate नहीं किया। क्या आप official documents भेज सकते हैं?"
        },
        "mr": {
            "default": "तुम्ही official documents पाठवू शकता? मी बैंकला विचारतो.",
            "upi": "मी माइया UPI app मध्ये तपासणी करेन. तुम्ही official bank email पाठवू शकता?",
            "digital_arrest": "मला माइया वकिलाशी बोलणे आवश्यक आहे. तुम्ही official documents पाठवू शकता?",
            "loan": "मी माइया credit score तपासेन. तुमची official website कोणती आहे?",
            "prize": "मी कोणत्याही lottery मध्ये सहभागी झालो नाही. तुम्ही official documents पाठवू शकता?"
        }
    }
    
    # Get language-specific replies
    lang_replies = replies.get(language, replies["en"])
    
    # Get scam-type specific reply or default
    scam_key = scam_type.lower().replace(" ", "_").replace("/", "_")
    if scam_key in lang_replies:
        return lang_replies[scam_key]
    else:
        return lang_replies["default"]


def generate_safety_message(language: str) -> str:
    """
    Generate safety warning message based on language.
    
    Args:
        language: Language code
        
    Returns:
        Safety message string
    """
    messages = {
        "en": "⚠️ Do NOT share OTP, passwords, or money. Block this number and report to 1930 (Cybercrime Helpline) or cybercrime.gov.in",
        "hi": "⚠️ कृपया OTP, पासवर्ड या पैसे किसी को न दें। इस नंबर को block करें और 1930 (Cybercrime Helpline) या cybercrime.gov.in पर report करें।",
        "mr": "⚠️ कृपया OTP, पासवर्ड किंवा पैसे कोणालाही देऊ नका. हा नंबर ब्लॉक करा आणि 1930 (Cybercrime Helpline) किंवा cybercrime.gov.in वर report करा."
    }
    
    return messages.get(language, messages["en"])


# ============================================================================
# Fallback Analysis (without LLM)
# ============================================================================

def analyze_message_rules_only(message: str) -> Dict:
    """
    Perform rule-based analysis only (fallback when Ollama unavailable).
    
    Args:
        message: The suspicious message to analyze
        
    Returns:
        Dictionary with analysis results
    """
    logger.info("📋 Running rule-based analysis only (no LLM)...")
    
    # Run rule-based analysis
    rule_result = rule_based_score(message)
    rule_score = rule_result.score
    language = rule_result.detected_language
    
    # Map categories to scam types (simplified)
    category_to_scam = {
        "financial": "UPI Phishing",
        "prize": "Lottery/Prize Scam",
        "investment": "Investment Scam",
        "loan": "Loan Scam",
        "authority": "Digital Arrest",
    }
    
    # Determine scam type from categories
    scam_type = "Other"
    for cat in rule_result.matched_categories:
        if cat in category_to_scam:
            scam_type = category_to_scam[cat]
            break
    
    # Generate explanation
    explanation = get_explanation(rule_result.matched_categories, language)
    
    # Determine high risk
    is_high_risk = rule_score >= HIGH_RISK_THRESHOLD
    
    # Generate safe reply if high risk
    safe_reply = None
    if is_high_risk:
        safe_reply = generate_default_safe_reply(language, scam_type)
    
    # Safety message
    safety_message = generate_safety_message(language)
    
    result = {
        "risk_score": rule_score,
        "scam_type": scam_type,
        "explanation": explanation,
        "high_risk": is_high_risk,
        "suggested_safe_reply": safe_reply,
        "language": language,
        "safety_message": safety_message,
        "_debug": {
            "rule_score": rule_score,
            "llm_score": None,
            "rule_categories": rule_result.matched_categories,
            "mode": "rules_only"
        }
    }
    
    return result


# ============================================================================
# Main Entry Point (for testing)
# ============================================================================

if __name__ == "__main__":
    import sys
    
    # Test messages
    test_messages = [
        # English
        "Your OTP is 123456. UPI transaction of Rs 5000 pending. Verify now or account will be blocked.",
        "Congratulations! You've won Rs 10,00,000 in lottery. Click here to claim now!",
        "This is SBI Bank. Your account will be closed in 24 hours. Update KYC immediately.",
        
        # Hindi
        "आपका OTP 123456 है। UPI से Rs 5000 कट गया। वेरीफाई करें।",
        "बधाई हो! आपने Rs 10,00,000 जीते हैं। तुरंत क्लिक करें।",
        
        # Marathi
        "तुमचा OTP 123456 आहे. UPI वर Rs 5000 कट झाला. व्हेरिफाय करा.",
    ]
    
    print("=" * 60)
    print("ScamShield Honeypot - Hybrid Analyzer Test")
    print("=" * 60)
    
    for i, msg in enumerate(test_messages):
        print(f"\n\n{'='*60}")
        print(f"TEST {i+1}: {msg[:50]}...")
        print(f"{'='*60}")
        
        # Run analysis
        result = asyncio.run(analyze_message(msg))
        
        print(f"\n📊 Risk Score: {result['risk_score']}%")
        print(f"🔴 High Risk: {result['high_risk']}")
        print(f"🏷️  Scam Type: {result['scam_type']}")
        print(f"📝 Explanation: {result['explanation']}")
        
        if result['suggested_safe_reply']:
            print(f"💬 Safe Reply: {result['suggested_safe_reply']}")
        
        print(f"\n⚠️  Safety Message: {result['safety_message']}")
        
        if "_debug" in result:
            print(f"\n🔍 Debug: {result['_debug']}")
