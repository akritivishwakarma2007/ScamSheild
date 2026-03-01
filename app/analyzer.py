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


# ============================================================================
# LLM Analysis Functions
# ============================================================================

async def call_ollama(message: str) -> Dict:
    """
    Call Ollama API for LLM analysis.
    
    Args:
        message: The suspicious message to analyze
        
    Returns:
        Dictionary with LLM analysis results
    """
    import ollama

    # Get configuration
    model = os.getenv("OLLAMA_MODEL", "gemma2:2b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))
    
    # Build prompt
    prompt = build_analysis_prompt(message)
    
    logger.info(f"🤖 Calling Ollama with model: {model}")
    
    try:
        # Call Ollama with async support
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
        
        # Extract response
        llm_response = response.get("response", "")
        
        # Parse JSON
        parsed = parse_llm_response(llm_response)
        
        if parsed and validate_response(parsed):
            logger.info(f"✅ LLM analysis successful: {parsed.get('risk_score', 0)}%")
            return parsed
        else:
            logger.warning("⚠️ LLM response parsing failed, using default")
            return get_default_response()
            
    except Exception as e:
        logger.error(f"❌ Ollama error: {str(e)}")
        return get_default_response()


def call_ollama_sync(message: str) -> Dict:
    """
    Synchronous wrapper for Ollama API call.
    
    Args:
        message: The suspicious message to analyze
        
    Returns:
        Dictionary with LLM analysis results
    """
    import ollama
    
    # Get configuration
    model = os.getenv("OLLAMA_MODEL", "gemma2:2b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))
    
    # Build prompt
    prompt = build_analysis_prompt(message)
    
    logger.info(f"🤖 Calling Ollama with model: {model}")
    
    try:
        response = ollama.generate(
            model=model,
            prompt=prompt,
            format="json",
            options={
                "temperature": temperature,
                "num_predict": 500,
            }
        )
        
        # Extract response
        llm_response = response.get("response", "")
        
        # Parse JSON
        parsed = parse_llm_response(llm_response)
        
        if parsed and validate_response(parsed):
            logger.info(f"✅ LLM analysis successful: {parsed.get('risk_score', 0)}%")
            return parsed
        else:
            logger.warning("⚠️ LLM response parsing failed, using default")
            return get_default_response()
            
    except Exception as e:
        logger.error(f"❌ Ollama error: {str(e)}")
        return get_default_response()


# ============================================================================
# Hybrid Analysis
# ============================================================================

async def analyze_message(message: str) -> Dict:
    """
    Perform hybrid analysis combining rule-based and LLM analysis.
    
    This function:
    1. Runs rule-based analysis (40% weight)
    2. Runs LLM analysis via Ollama (60% weight)
    3. Combines scores for final risk assessment
    4. Generates safe reply for high-risk messages
    
    Args:
        message: The suspicious message to analyze
        
    Returns:
        Dictionary with complete analysis results
    """
    logger.info("🔍 Starting hybrid analysis...")
    
    # Step 1: Rule-based analysis
    logger.info("📋 Running rule-based analysis...")
    rule_result = rule_based_score(message)
    rule_score = rule_result.score
    language = rule_result.detected_language
    
    logger.info(f"   Rule score: {rule_score}% ({', '.join(rule_result.matched_categories)})")
    
    # Step 2: LLM analysis
    logger.info("🤖 Running LLM analysis...")
    llm_result = call_ollama_sync(message)
    llm_score = llm_result.get("risk_score", 50)
    
    logger.info(f"   LLM score: {llm_score}%")
    
    # Step 3: Combine scores
    final_score = int((rule_score * RULE_WEIGHT) + (llm_score * LLM_WEIGHT))
    final_score = min(max(final_score, 0), 100)  # Clamp to 0-100
    
    logger.info(f"   Final score: {final_score}%")
    
    # Step 4: Determine scam type
    # Prefer LLM classification but fallback to rule-based
    scam_type = llm_result.get("scam_type", "Other")
    
    # Step 5: Generate explanation
    # Combine rule-based and LLM explanations
    rule_explanation = get_explanation(rule_result.matched_categories, language)
    llm_explanation = llm_result.get("explanation", "")
    
    if llm_explanation:
        explanation = llm_explanation
    else:
        explanation = rule_explanation
    
    # Step 6: Determine if high risk
    is_high_risk = final_score >= HIGH_RISK_THRESHOLD
    
    # Step 7: Generate safe reply for high risk
    safe_reply = None
    if is_high_risk:
        safe_reply = llm_result.get("safe_reply")
        if not safe_reply:
            safe_reply = generate_default_safe_reply(language, scam_type)
    
    # Step 8: Generate safety message
    safety_message = generate_safety_message(language)
    
    # Step 9: Build final result
    result = {
        "risk_score": final_score,
        "scam_type": scam_type,
        "explanation": explanation,
        "high_risk": is_high_risk,
        "suggested_safe_reply": safe_reply,
        "language": language,
        "safety_message": safety_message,
        # Debug info (can be removed in production)
        "_debug": {
            "rule_score": rule_score,
            "llm_score": llm_score,
            "rule_categories": rule_result.matched_categories
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
