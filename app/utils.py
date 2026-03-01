"""
ScamShield Honeypot - Utility Functions
========================================
This module contains utility functions for the ScamShield application.

Author: Cracked Team - AI for Bharat Hackathon
Team Leader: Lakshya Kumar Singh
"""

import re
from typing import Tuple


# ============================================================================
# Message Validation
# ============================================================================

def validate_message(message: str) -> Tuple[bool, str]:
    """
    Validate the input message before analysis.
    
    Args:
        message: The message to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check if message is empty
    if not message:
        return False, "Message cannot be empty."
    
    # Check if message is just whitespace
    if not message.strip():
        return False, "Message cannot be empty or whitespace."
    
    # Check minimum length
    if len(message.strip()) < 3:
        return False, "Message is too short. Please provide a more complete message."
    
    # Check maximum length
    if len(message) > 5000:
        return False, "Message is too long. Maximum 5000 characters allowed."
    
    # Check for only special characters
    if re.match(r'^[^a-zA-Z0-9\u0900-\u097F]+$', message.strip()):
        return False, "Message must contain some text content."
    
    return True, ""


# ============================================================================
# Text Processing
# ============================================================================

def normalize_text(text: str) -> str:
    """
    Normalize text for processing.
    
    Args:
        text: Input text
        
    Returns:
        Normalized text
    """
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Remove zero-width characters
    text = text.replace('\u200b', '')
    text = text.replace('\u200c', '')
    text = text.replace('\u200d', '')
    text = text.replace('\ufeff', '')
    
    return text.strip()


def extract_urls(text: str) -> list:
    """
    Extract URLs from text.
    
    Args:
        text: Input text
        
    Returns:
        List of URLs found
    """
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def extract_phone_numbers(text: str) -> list:
    """
    Extract phone numbers from text.
    
    Args:
        text: Input text
        
    Returns:
        List of phone numbers found
    """
    # Indian phone number patterns
    patterns = [
        r'\+91[\s\-]?\d{10}',
        r'0\d{10}',
        r'\d{10}',
    ]
    
    phones = []
    for pattern in patterns:
        phones.extend(re.findall(pattern, text))
    
    return phones


# ============================================================================
# Language Utilities
# ============================================================================

def get_language_name(code: str) -> str:
    """
    Get full language name from code.
    
    Args:
        code: Language code (en, hi, mr)
        
    Returns:
        Full language name
    """
    names = {
        "en": "English",
        "hi": "Hindi",
        "mr": "Marathi"
    }
    return names.get(code, "English")


# ============================================================================
# Scam Type Utilities
# ============================================================================

SCAM_TYPES = [
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

def is_valid_scam_type(scam_type: str) -> bool:
    """
    Check if scam type is valid.
    
    Args:
        scam_type: Scam type string
        
    Returns:
        True if valid, False otherwise
    """
    return scam_type in SCAM_TYPES


# ============================================================================
# Response Formatting
# ============================================================================

def format_risk_score(score: int) -> str:
    """
    Format risk score with appropriate label.
    
    Args:
        score: Risk score (0-100)
        
    Returns:
        Formatted string
    """
    if score < 25:
        return f"{score}% - Low Risk"
    elif score < 50:
        return f"{score}% - Low-Medium Risk"
    elif score < 75:
        return f"{score}% - Medium-High Risk"
    elif score < 90:
        return f"{score}% - High Risk"
    else:
        return f"{score}% - Critical Risk"


# ============================================================================
# Debug Utilities
# ============================================================================

def get_debug_info(result: dict) -> dict:
    """
    Extract debug information from result.
    
    Args:
        result: Analysis result dictionary
        
    Returns:
        Debug info dictionary
    """
    debug = result.get("_debug", {})
    
    return {
        "rule_score": debug.get("rule_score"),
        "llm_score": debug.get("llm_score"),
        "rule_categories": debug.get("rule_categories", []),
        "mode": debug.get("mode", "hybrid")
    }


# ============================================================================
# Main Entry Point (for testing)
# ============================================================================

if __name__ == "__main__":
    # Test validation
    test_messages = [
        "",
        "   ",
        "ab",
        "This is a test message with some content for validation.",
        "आपका OTP 123456 है। UPI से पैसे कट गए।",
        "a" * 5001,
    ]
    
    print("Testing message validation:")
    print("=" * 50)
    
    for msg in test_messages:
        is_valid, error = validate_message(msg)
        print(f"Message: '{msg[:30]}...' - Valid: {is_valid}")
        if not is_valid:
            print(f"  Error: {error}")
        print()
    
    # Test URL extraction
    test_text = "Visit https://example.com or call 9876543210"
    print("\nTesting URL extraction:")
    print(f"URLs: {extract_urls(test_text)}")
    print(f"Phones: {extract_phone_numbers(test_text)}")
