"""
ScamShield Honeypot - Rule-Based Scoring Module
================================================
This module handles rule-based scam detection using keyword matching
for common Indian scam patterns. Supports English, Hindi, and Marathi.

Enhanced with comprehensive patterns, URL/phone deep analysis, and 
improved language detection for code-mixed text.

Author: Cracked Team - AI for Bharat Hackathon
Team Leader: Lakshya Kumar Singh
"""

import re
from typing import Dict, List, Tuple
from dataclasses import dataclass
from typing import NamedTuple

# ============================================================================
# Scam Pattern Keywords - ENHANCED
# ============================================================================

# Urgency/Threat keywords (high weight) - ENHANCED
URGENCY_KEYWORDS = {
    "en": [
        # Basic urgency
        r"\b(urgent|immediate|now|right away|within \d+ (hour|min|minute|seconds?))\b",
        r"\b(expire|expiring|expiry|deadline|limited time|today only)\b",
        r"\b(last chance|don'?t miss|act now|hurry)\b",
        r"\b(block|suspend|close|freeze|terminate)\b.*\b(account|account|upi)\b",
        r"\b(24 hours?|48 hours?|72 hours?)\b",
        # Enhanced urgency patterns
        r"\b(last\s*day|only\s*few\s*hours|before\s*it'?s\s*too\s*late)\b",
        r"\b(immediate\s*action\s*required|respond\s*within)\b",
        r"\b(your\s*account\s*will\s*be\s*(blocked|closed|terminated|frozen))\b",
        r"\b(verify\s*now|confirm\s*immediately|verify\s*your\s*account)\b",
        r"\b(failure\s*to\s*(comply|respond|verify|update))\b",
        r"\b(last\s*warning|final\s*notice|final\s*call)\b",
        r"\b(don'?t\s*wait|don'?t\s*delay|don'?t\s*ignore)\b",
        r"\b(will\s*be\s*(suspended|blocked|deactivated|closed))\b.*\b(hours?|minutes?|days?)\b",
    ],
    "hi": [
        r"तुरंत|अभी|फ़ौरन|जल्दी|बाबत",
        r"समाप्त|समाप्त हो रहा|डेडलाइन",
        r"ब्लॉक|सस्पेंड|बंद|फ्रीज",
        r"24 घंटे|48 घंटे|72 घंटे",
        r"आज ही|लास्ट चांस",
        # Enhanced Hindi urgency
        r"जल्दी\s*करें|तुरंत\s*करें|फ़ौरन\s*करें",
        r"अभी\s*वेरिफाई|अभी\s*क्लिक\s*करें|अभी\s*जवाब\s*दें",
        r"आपका\s*खाता\s*(बंद|ब्लॉक|सस्पेंड)\s*हो\s*जाएगा",
        r"वक्त\s*रहते|समय\s*रहते|देर\s*न\s*करें",
        r"आखिरी\s*चांस|आखिरी\s*मौका|आखिरी\s*चेतावनी",
        r"नहीं\s*तो|वरना|अगर\s*नहीं\s*किया\s*तो",
    ],
    "mr": [
        r"ताबडतोब|आता|लगेच|घाई",
        r"संपणार|मुदत|बंद",
        r"ब्लॉक|सस्पेंड|बंद",
        r"24 तास|48 तास",
        # Enhanced Marathi urgency
        r"लगेच\s*करा|ताबडतोब\s*करा",
        r"तुमचे\s*खाते\s*(बंद|ब्लॉक)\s*होईल",
        r"वेळ\s*संपण्याआधी|वेळ\s*राहिल्याआधी",
    ]
}

# Financial keywords (medium-high weight) - ENHANCED
FINANCIAL_KEYWORDS = {
    "en": [
        # Basic financial
        r"\b(otp|one.?time.?password)\b",
        r"\b(upi|payment|transaction|rs\.?|₹|rupee|inr)\b",
        r"\b(bank|account|sbi|icici|hdfc|axis|pnb)\b",
        r"\b(kyc|know.?your.?customer)\b",
        r"\b(refund|return|reimbursement)\b",
        r"\b(wire.?transfer|neft|rtgs|imps)\b",
        r"\b(wallet|paytm|phonepe|gpay|googlepay)\b",
        # Enhanced financial patterns
        r"\b(pin\s*number|pin\s*code|atm\s*card|card\s*details)\b",
        r"\b(debit\s*card|credit\s*card|card\s*number|cvv)\b",
        r"\b(account\s*number|ifsc\s*code|bank\s*details)\b",
        r"\b(money\s*transfer|send\s*money|transfer\s*money|pay\s*money)\b",
        r"\b(transaction\s*(failed|pending|declined|successful))\b",
        r"\b(₹\s*\d+[\d,]*|\d+\s*₹)\b",  # Currency amounts
        r"\b(amount|balance|available\s*balance)\b",
        r"\b(wallet\s*(balance|limit|verified)|kYC\s*verified)\b",
        r"\b(sweep|frequent|minor)\b.*\b(account|transaction)\b",
        r"\b(credit|debit)\s*Rs\.?|Rs\.?\s*(credit|debit)\b",
    ],
    "hi": [
        r"ओटीपी|पासवर्ड",
        r"यूपीआई|भुगतान|लेन-देन|रुपए|पैसे",
        r"बैंक|खाता|केवाईसी",
        r"रिफंड|वापसी",
        r"वॉलेट|पेटीएम|गूगलपे",
        # Enhanced Hindi financial
        r"पिन\s*नंबर|कार्ड\s*नंबर|CVV",
        r"खाता\s*नंबर|IFSC\s*कोड|बैंक\s*डिटेल्स",
        r"पैसे\s*भेजें|पैसे\s*ट्रांसफर|पैसे\s*भुगतान",
        r"ट्रांजैक्शन\s*(फेल|पेंडिंग|सक्सेस)",
        r"रुपये\s*\d+|₹\s*\d+",
        r"बैलेंस|अकाउंट\s*बैलेंस",
    ],
    "mr": [
        r"ओटीपी|पासवर्ड",
        r"यूपीआई|पैसे|रुपे",
        r"बैंक|खाते|केवायसी",
        r"रिफंड|परत",
        # Enhanced Marathi financial
        r"पिन\s*नंबर|कार्ड\s*नंबर",
        r"खाता\s*नंबर|बैंक\s*माहिती",
        r"पैसे\s*पाठवा|पैसे\s*ट्रांसफर",
        r"रुपये\s*\d+",
    ]
}

# Authority impersonation keywords (high weight) - ENHANCED
AUTHORITY_KEYWORDS = {
    "en": [
        # Basic authority
        r"\b(police|cbi|cibil|trai|sebi|rbi)\b",
        r"\b(court|law|legal|advocate|lawyer)\b",
        r"\b(govt|government|income.?tax|it.?dept)\b",
        r"\b(mci|medical council|ira)\b",
        r"\b(digital.?arrest)\b",
        r"\b(official|authority|government.?website)\b",
        # Enhanced authority patterns
        r"\b(this\s*is\s*(police|sbi|icici|hdfc|bank|court|cibil))\b",
        r"\b(calling\s*from|representative|customer\s*care)\b",
        r"\b(government\s*(official|employee|department))\b",
        r"\b(income\s*tax\s*department|it\s*department|tax\s*department)\b",
        r"\b(central\s*bureau\s*of\s*investigation|cbi)\b",
        r"\b( TRAI|sebi|rbi\s*bank)\b",
        r"\b( FIR|police\s*station|case\s*filed)\b",
        r"\b(arrest\s*warrant|arranty\s*arrest|legal\s*notice)\b",
        r"\b(your\s*aadhar|your\s*pan|your\s*adhaar).*\b(linked|verification)\b",
        r"\b(national\s*crime|cyber\s*crime)\b.*\b(branch|portal)\b",
        r"\b(ministry|election\s*commission|election)\b",
    ],
    "hi": [
        r"पुलिस|सीबीआई|कोर्ट|अदालत",
        r"कानून|वकील|सरकार",
        r"आयकर|इनकम टैक्स",
        r"डिजिटल अरेस्ट",
        r"सरकारी|आधिकारिक",
        # Enhanced Hindi authority
        r"यह\s*(पुलिस|सीबीआई|कोर्ट|बैंक)\s*है",
        r"सरकार\s*का\s*(कर्मचारी|अधिकारी|विभाग)",
        r"आयकर\s*विभाग|इनकम\s*टैक्स\s*डिपार्टमेंट",
        r"एफआईआर|पुलिस\s*स्टेशन|मुकदमा",
        r"गिरफ्तारी\s*वारंट|गिरफ्तार\s*होगे",
        r"अदालत\s*का\s*नोटिस|कोर्ट\s*का\s*नोटिस",
        r"आपका\s*आधार|आपका\s*पैन.*\b(लिंक|वेरिफाई)\b",
        r"राष्ट्रीय\s*अपराध|साइबर\s*अपराध",
    ],
    "mr": [
        r"पोलीस|कोर्ट|कायदा",
        r"सरकार|शासन",
        r"डिजिटल अरेस्ट",
        # Enhanced Marathi authority
        r"हे\s*(पोलीस|कोर्ट|बैंक)\s*आहे",
        r"सरकारी\s*कर्मचारी|सरकारी\s*अधिकारी",
        r"पोलीस\s*ठाणे|FIR",
        r"अटक\s*वारंट|शिक्षा\s*नोटीस",
    ]
}

# Prize/Lottery keywords (high weight) - ENHANCED
PRIZE_KEYWORDS = {
    "en": [
        # Basic prize
        r"\b(winner|won|lottery|jackpot|prize|reward|gift)\b",
        r"\b(claim|congratulations|selected|lucky)\b",
        r"\brore|lakh|₹\d+,(c?\d{3,})\b",
        r"\b(free|free.?gift|no.?cost)\b",
        # Enhanced prize patterns
        r"\b(you\s*(have\s*)?won|congratulations.*you\s*won)\b",
        r"\b(selected\s*(as\s*)?(winner|lucky))\b",
        r"\b(lucky\s*(winner|draw|number)|lucky\s*customer)\b",
        r"\b(claim\s*your\s*(prize|money|gift)|claim\s*now)\b",
        r"\b(free\s*(gift|iphone|mobile|laptop|prize)|no\s*payment\s*required)\b",
        r"\b(क्रोड़|लाख|करोड़|₹\d+\s*(lakh|crore)|million|billion)\b",
        r"\b(offer\s*valid\s*limited|exclusive\s*offer|special\s*offer)\b",
        r"\b(क्लिक\s*करें|click\s*here\s*to\s*claim|grab\s*your)\b",
    ],
    "hi": [
        r"विजेता|जीता|लॉटरी|इनाम",
        r"दावा|बधाई|चुना",
        r"करोड़|लाख|मुफ्त",
        # Enhanced Hindi prize
        r"आपने\s*जीते\s*हो|बधाई\s*आपने\s*जीते",
        r"विजेता\s*चुने\s*गए|लकी\s*विनर",
        r"अपना\s*(इनाम|पैसा|रुपये)\s*लें|दावा\s*करें",
        r"मुफ्त\s*(गिफ्ट|ईयरफोन|मोबाइल|लैपटॉप)",
        r"सीमित\s*ऑफर|विशेष\s*ऑफर|एक्सक्लूसिव\s*ऑफर",
    ],
    "mr": [
        r"विजेता|जिंकल|बक्षीस",
        r"कोटी|लाख|मोफत",
        # Enhanced Marathi prize
        r"तुम्ही\s*जिंकला|अभिनंदन\s*तुम्ही\s*जिंकला",
        r"विजेता\s*निवडला|लकी\s*कस्टमर",
        r"तुमचं\s*बक्षीस\s*घ्या|claim\s*करा",
    ]
}

# Investment/Work from home keywords (high weight) - ENHANCED
INVESTMENT_KEYWORDS = {
    "en": [
        # Basic investment
        r"\b(invest|investment|mutual.?fund|stock|share)\b",
        r"\b(crypto|bitcoin|forex|trading)\b",
        r"\b(work from home|part.?time|online.?job|freelance)\b",
        r"\b(income|earn|profit|return|interest)\b",
        r"\b(\d+%\s*(profit|return|interest|monthly|year))\b",
        r"\b(guaranteed|sure.?win|risk.?free)\b",
        # Enhanced investment patterns
        r"\b(double\s*your\s*(money|investment)|triple\s*your)\b",
        r"\b(100%\s*(return|profit|gain)|guaranteed\s*returns?)\b",
        r"\b(invest\s*(now|today|in)|start\s*investing)\b",
        r"\b(online\s*(job|work|earning|making))\b",
        r"\b(work\s*from\s*(home|anywhere)|home\s*based\s*job)\b",
        r"\b(daily\s*income|weekly\s*income|monthly\s*income)\b",
        r"\b(binary\s*option|mlm|pyramid\s*scheme|ponzi)\b",
        r"\b(cryptocurrency|crypto\s*trading|bitcoin\s*investment)\b",
        r"\b(real\s*estate|property\s*investment|plot\s*investment)\b",
    ],
    "hi": [
        r"निवेश|म्यूचुअल फंड|शेयर",
        r"क्रिप्टो|बिटकॉइन|ट्रेडिंग",
        r"घर से काम|ऑनलाइन जॉब",
        r"कमाई|मुनाफा|रिटर्न",
        r"गारंटी|बिना रिस्क",
        # Enhanced Hindi investment
        r"अपने\s*पैसे\s*(दोगुने|तिगुने)\s*करें",
        r"गारंटीड\s*रिटर्न|100%\s*रिटर्न",
        r"ऑनलाइन\s*(कमाई|पैसा\s*कमाएं)",
        r"घर\s*से\s*काम|वर्क\s*फ्रॉम\s*होम",
        r"रोज़\s*की\s*कमाई|साप्ताहिक\s*आय",
        r"बाइनरी\s*ऑप्शन|एमएलएम|पिरामिड\s*स्कीम",
    ],
    "mr": [
        r"गुंतवणूक|शेअर",
        r"क्रिप्टो|व्यापार",
        r"घरून काम|ऑनलाइन जॉब",
        r"नफा|फायदा",
        # Enhanced Marathi investment
        r"तुमचे\s*पैसे\s*(दुप्पट|तिप्पट)\s*करा",
        r"गरंटीड\s*फायदा|100%\s*फायदा",
        r"ऑनलाइन\s*कमाई|घरून\s*काम",
    ]
}

# Loan/Credit keywords (medium weight) - ENHANCED
LOAN_KEYWORDS = {
    "en": [
        # Basic loan
        r"\b(loan|credit|personal.?loan|instant.?loan)\b",
        r"\b(approved|pre-?approved|eligible)\b",
        r"\b(interest.?rate|emi|processing.?fee)\b",
        r"\b(cibil|score|credit.?score)\b",
        # Enhanced loan patterns
        r"\b(instant\s*loan|quick\s*loan|same\s*day\s*loan)\b",
        r"\b(loan\s*(approved|eligible|available)|sanctioned)\b",
        r"\b(low\s*interest\s*rate|best\s*interest\s*rate)\b",
        r"\b(no\s*(documents?|collateral|security|paperwork))\b",
        r"\b(online\s*loan|apply\s*loan\s*(now|online))\b",
        r"\b(business\s*loan|education\s*loan|home\s*loan)\b",
        r"\b(personal\s*loan.*\d+%\b|loan.*\d+%.*interest)\b",
    ],
    "hi": [
        r"लोन|ऋण|कर्ज|लेनदेन",
        r"स्वीकृत|पात्र",
        r"ब्याज|ईएमआई|प्रोसेसिंग फी",
        r"सिबिल|स्कोर",
        # Enhanced Hindi loan
        r"तुरंत\s*लोन|फटाफट\s*लोन|आज\s*ही\s*लोन",
        r"लोन\s*(स्वीकृत|पात्र|उपलब्ध)",
        r"कम\s*ब्याज\s*दर|सबसे\s*कम\s*ब्याज",
        r"बिना\s*(दस्तावेज़|गवाह|सिक्योरिटी)\s*के",
        r"ऑनलाइन\s*लोन|लोन\s*के\s*लिए\s*आवेदन",
    ],
    "mr": [
        r"लोन|कर्ज",
        r"मंजूर|पात्र",
        r"व्याज|ईएमआई",
        # Enhanced Marathi loan
        r"त्वरित\s*लोन|लगेच\s*लोन",
        r"लोन\s*(मंजूर|पात्र|उपलब्ध)",
        r"कम\s*व्याज\s*दर",
    ]
}

# Tech Support / Fake Call Center keywords - NEW
TECH_SUPPORT_KEYWORDS = {
    "en": [
        r"\b(tech.?support|technical.?support|computer.?support)\b",
        r"\b(microsoft|windows|google|amazon|apple)\s*(support|care)\b",
        r"\b(install\s*(anydesk|teamviewer|quickassist|realvnc))\b",
        r"\b(remote\s*access|remote\s*desktop|your\s*computer\s*is\s*(infected|compromised))\b",
        r"\b(virus\s*alert|malware\s*detected|system\s*infected)\b",
        r"\b(call\s*us\s*at|contact\s*us\s*at|helpline)\b.*\d{10,}",
        r"\b(your\s*(computer|laptop|mobile|phone)\s*is\s*(hack|compromised))\b",
        r"\b(suspicious\s*activity\s*detected|unauthorized\s*access)\b",
    ],
    "hi": [
        r"टेक\s*सपोर्ट|टेक्निकल\s*सपोर्ट",
        r"माइक्रोसॉफ्ट|गूगल|अमेज़न\s*सपोर्ट",
        r"रिमोट\s*एक्सेस|आपका\s*कंप्यूटर\s*हैक\s*हो\s*गया",
        r"वायरस\s*अलर्ट|मैलवेयर\s*डिटेक्ट",
        r"आपका\s*फोन\s*हैक\s*हो\s*गया",
    ],
    "mr": [
        r"टेक\s*सपोर्ट",
        r"रिमोट\s*एक्सेस|तुमचा\s*संगणक\s*हैक\s*झाला",
    ]
}

# Fake KYC / Identity verification - NEW
KYC_KEYWORDS = {
    "en": [
        r"\b(kyc\s*(update|verification|required|pending|expired))\b",
        r"\b(your\s*kyc\s*is\s*(pending|expired|failed|not\s*done))\b",
        r"\b(update\s*your\s*(kyc|pan|aadhar|adhar))\b",
        r"\b(aadhar\s*(link|verification|update)|adhaar)\b",
        r"\b(pan\s*card\s*(link|verify|update))\b",
        r"\b(verify\s*your\s*(identity|account|details))\b",
        r"\b(link\s*aadhar|update\s*aadhar|adhar\s*se\s*upi)\b",
    ],
    "hi": [
        r"केवाईसी\s*(अपडेट|वेरिफिकेशन|जरूरी)",
        r"आपका\s*केवाईसी\s*(पेंडिंग|एक्सपायर्ड|नहीं\s*हुआ)\b",
        r"अपना\s*(आधार|पैन)\s*अपडेट\s*करें",
        r"आधार\s*लिंक|पैन\s*कार्ड\s*लिंक",
    ],
    "mr": [
        r"केवायसी\s*अपडेट|केवायसी\s*पूर्ण\s*करा",
        r"तुमचा\s*केवायसी\s*(लाटींग|संपलेला)",
        r"आधार\s*लिंक|पॅन\s*कार्ड\s*लिंक",
    ]
}

# Link/URL patterns - ENHANCED with deep analysis
URL_PATTERNS = [
    # Basic URL patterns
    r"http[s]?://",
    r"www\.",
    r"\.(com|org|net|in|co|info|biz|io)\b",
    r"bit\.ly|tinyurl|shorturl",
    # Suspicious TLDs
    r"\.tk$|\.ml$|\.ga$|\.cf$|\.gq$|\.xyz$|\.top$|\.work$|\.click$|\.link$",
    # Suspicious URL patterns
    r"qrcode?|scan|barcode",
    r"login|signin|verify|update|secure|confirm",
    r"bank|upi|payment|account",
    # IP address in URL
    r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    # Suspicious domains
    r"(sbi|icici|hdfc|axis|pnb|yesbank|bank).*(login|verify|update|secure)",
    r"(paytm|phonepe|gpay|amazon).*(offer|reward|cashback|claim)",
    # URL shorteners
    r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly",
]

# Phone number patterns - ENHANCED
PHONE_PATTERNS = [
    r"\b\d{10}\b",  # 10 digit
    r"\b\+91[-]?\d{10}\b",  # +91 format
    r"\b0\d{10}\b",  # 0 prefix
    r"\b\+1[-]?\d{10}\b",  # US format
    r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Generic
]

# Suspicious phone number prefixes (often used in scams)
SUSPICIOUS_PHONE_PREFIXES = [
    r"\b9999\d{6}\b",  # Often used for spam
    r"\b8888\d{6}\b",
    r"\b7777\d{6}\b",
    r"\b9\d{9}\b",  # Starting with 9 (mobile)
]

# ============================================================================
# Weight Configuration - ENHANCED
# ============================================================================

# Base weights for each category (0-100 scale)
CATEGORY_WEIGHTS = {
    "urgency": 15,
    "financial": 20,
    "authority": 20,
    "prize": 15,
    "investment": 15,
    "loan": 10,
    "url_present": 5,
    "tech_support": 15,
    "kyc": 15,
}

# High-risk combinations (boost score when found together)
RISKY_COMBINATIONS = [
    # OTP + Urgency + Financial = Very High Risk
    (["urgency", "financial"], 25),
    # Authority + Urgency = High Risk (Digital Arrest)
    (["authority", "urgency"], 30),
    # Prize + URL = Phishing
    (["prize", "url_present"], 20),
    # Investment + Promise of returns = Scam
    (["investment", "prize"], 20),
    # Tech Support + Remote access = Scam
    (["tech_support", "financial"], 25),
    # KYC + Urgency = Fake KYC
    (["kyc", "urgency"], 25),
]


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class RuleMatch:
    """Represents a matched rule pattern."""
    category: str
    matched_text: str
    weight: float


@dataclass
class RuleResult:
    """Result of rule-based analysis."""
    score: float  # 0-100
    matched_categories: List[str]
    matches: List[RuleMatch]
    detected_language: str


# ============================================================================
# Language Detection - IMPROVED for code-mixed text
# ============================================================================

def detect_language(text: str) -> str:
    """
    Improved heuristic language detection for Hindi, Marathi, and English.
    Enhanced for code-mixed (Hinglish, Manglish) text detection.
    
    Args:
        text: Input text to analyze
        
    Returns:
        Language code: 'en', 'hi', or 'mr'
    """
    # Hindi Devanagari script characters
    hindi_chars = len(re.findall(r'[\u0900-\u097F]', text))
    
    # Marathi uses same Devanagari script, but also uses some unique chars
    # For simplicity, we'll treat both as Hindi for keyword matching
    # since they share most characters
    
    # Count common Hindi words (expanded list)
    hindi_words = len(re.findall(
        r'(आपका|आपने|आपको|है|हैं|किया|करें|होगा|इस|यह|और|या|से|में|का|की|को|हूं|था|थे|थी|नहीं|कभी|तब|तू|तुम|मैं|हम|क्या|कौन|कहां|कैसे|कितना|सब|प्रत्येक|एक|दो|तीन|चार|पांच)',
        text
    ))
    
    # Marathi specific (expanded list)
    marathi_words = len(re.findall(
        r'(तुमचा|तुमची|आहे|केले|होंदे|हे|तो|आणि|किंवा|यामुळे|मी|तू|आम्ही|त्याचा|त्याची|त्याला|त्याला|हे|ती|ते|पण|म्हणून|केला|केली|केले|दिले|दिली|घेतले)',
        text
    ))
    
    # English detection (expanded list)
    english_words = len(re.findall(
        r'\b(the|is|are|was|were|have|has|been|your|you|this|that|from|in|to|and|or|but|if|then|else|when|where|what|who|how|why|all|some|any|no|not|only|just|can|could|should|would|will|would|do|does|did|make|made|get|got|come|came|see|saw|know|knew|say|said|tell|told|think|thought|feel|felt|want|want|need|need|try|tried|use|used|find|found|give|gave|take|took)\b',
        text.lower()
    ))
    
    # Calculate scores
    total = hindi_chars + english_words + 1
    
    # Ratios
    hindi_ratio = (hindi_chars + hindi_words) / total
    marathi_ratio = marathi_words / total
    english_ratio = english_words / total
    
    # Language detection logic
    # Lower threshold for Devanagari to catch more Hindi/Marathi
    if hindi_chars > 2 or hindi_ratio > 0.15:
        return "hi"
    elif english_ratio > 0.2:
        return "en"
    else:
        # Default to English
        return "en"


# ============================================================================
# Scoring Functions - ENHANCED
# ============================================================================

def calculate_category_score(
    text: str,
    patterns: Dict[str, List[str]],
    language: str
) -> Tuple[float, List[str]]:
    """
    Calculate score for a category based on keyword matching.
    
    Args:
        text: Input text
        patterns: Dictionary of language -> pattern list
        language: Language code
        
    Returns:
        Tuple of (score 0-100, list of matched patterns)
    """
    text_lower = text.lower()
    matched = []
    
    # Check patterns for detected language and English
    languages_to_check = [language]
    if language != "en":
        languages_to_check.append("en")
    
    for lang in set(languages_to_check):
        if lang not in patterns:
            continue
            
        for pattern in patterns[lang]:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    matched.append(pattern)
            except re.error:
                # Handle invalid regex
                continue
    
    # Calculate score based on number of matches
    # More granular scoring
    if len(matched) == 0:
        return 0.0, []
    elif len(matched) == 1:
        return 30.0, matched
    elif len(matched) == 2:
        return 60.0, matched
    elif len(matched) == 3:
        return 80.0, matched
    else:
        return 95.0, matched


def calculate_url_score(text: str) -> Tuple[float, List[str]]:
    """
    Enhanced check for suspicious URL/link patterns with deep analysis.
    
    Args:
        text: Input text
        
    Returns:
        Tuple of (score 0-100, list of matched patterns)
    """
    score = 0.0
    matched = []
    
    for pattern in URL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)
    
    if len(matched) > 0:
        # More granular scoring based on number of URL patterns found
        score = min(30.0 * len(matched), 90.0)
    
    return score, matched


def calculate_phone_analysis(text: str) -> Tuple[bool, List[str]]:
    """
    Analyze phone numbers in text for suspicious patterns.
    
    Args:
        text: Input text
        
    Returns:
        Tuple of (has_suspicious_phone, list of phone numbers)
    """
    phones = []
    suspicious = False
    
    # Extract phone numbers
    for pattern in PHONE_PATTERNS:
        matches = re.findall(pattern, text)
        phones.extend(matches)
    
    # Check for suspicious prefixes
    for pattern in SUSPICIOUS_PHONE_PREFIXES:
        if re.search(pattern, text):
            suspicious = True
            break
    
    return suspicious, phones


# ============================================================================
# Main Rule-Based Analysis - ENHANCED
# ============================================================================

def rule_based_score(text: str) -> RuleResult:
    """
    Perform rule-based scam detection on the input text.
    
    Enhanced with:
    - More scam categories (tech support, KYC)
    - URL deep analysis
    - Phone number analysis
    - Risky combination detection
    
    Args:
        text: The suspicious message to analyze
        
    Returns:
        RuleResult with score and matched patterns
    """
    # Handle empty or invalid input
    if not text or not text.strip():
        return RuleResult(
            score=0,
            matched_categories=[],
            matches=[],
            detected_language="en"
        )
    
    # Detect language
    language = detect_language(text)
    
    # Initialize tracking
    total_score = 0.0
    all_matches = []
    matched_categories = []
    
    # Calculate scores for each category - NOW INCLUDING NEW CATEGORIES
    category_patterns = {
        "urgency": URGENCY_KEYWORDS,
        "financial": FINANCIAL_KEYWORDS,
        "authority": AUTHORITY_KEYWORDS,
        "prize": PRIZE_KEYWORDS,
        "investment": INVESTMENT_KEYWORDS,
        "loan": LOAN_KEYWORDS,
        "tech_support": TECH_SUPPORT_KEYWORDS,  # NEW
        "kyc": KYC_KEYWORDS,  # NEW
    }
    
    for category, patterns in category_patterns.items():
        score, matches = calculate_category_score(text, patterns, language)
        
        if score > 0:
            # Apply category weight
            weighted_score = score * (CATEGORY_WEIGHTS.get(category, 10) / 100)
            total_score += weighted_score
            matched_categories.append(category)
            
            for match in matches:
                all_matches.append(RuleMatch(
                    category=category,
                    matched_text=match,
                    weight=weighted_score
                ))
    
    # Check for URLs with deep analysis
    url_score, url_matches = calculate_url_score(text)
    if url_score > 0:
        total_score += url_score * 0.05  # 5% weight for URL
        matched_categories.append("url")
        for match in url_matches:
            all_matches.append(RuleMatch(
                category="url",
                matched_text=match,
                weight=url_score * 0.05
            ))
    
    # Phone number analysis
    has_suspicious_phone, phones = calculate_phone_analysis(text)
    if has_suspicious_phone and len(phones) > 0:
        # Small boost for suspicious phone numbers
        total_score = min(total_score + 5, 100)
        matched_categories.append("suspicious_phone")
        all_matches.append(RuleMatch(
            category="suspicious_phone",
            matched_text=f"Suspicious phone: {phones[0]}",
            weight=5
        ))
    
    # Check for risky combinations and apply boosts
    for combo_categories, boost in RISKY_COMBINATIONS:
        # Check if all categories in combination are present
        if all(cat in matched_categories for cat in combo_categories):
            total_score = min(total_score + boost, 100)
    
    # Normalize score to 0-100
    total_score = min(total_score, 100)
    
    # Boost score if multiple categories matched
    if len(matched_categories) >= 3:
        total_score = min(total_score + 10, 100)
    elif len(matched_categories) >= 5:
        total_score = min(total_score + 20, 100)
    elif len(matched_categories) >= 7:
        total_score = min(total_score + 25, 100)
    
    return RuleResult(
        score=round(total_score),
        matched_categories=matched_categories,
        matches=all_matches,
        detected_language=language
    )


# ============================================================================
# Helper Functions - ENHANCED
# ============================================================================

def get_explanation(matched_categories: List[str], language: str) -> str:
    """
    Generate explanation based on matched categories.
    
    Args:
        matched_categories: List of matched category names
        language: Language code for explanation
        
    Returns:
        Human-readable explanation
    """
    explanations = {
        "en": {
            "urgency": "Uses urgent/threatening language to pressure quick action",
            "financial": "Contains financial transaction or payment keywords",
            "authority": "Impersonates authority (police, bank, government)",
            "prize": "Claims you've won a prize or lottery",
            "investment": "Offers investment or work-from-home opportunity",
            "loan": "Promises instant loan or credit",
            "url": "Contains suspicious links or URLs",
            "tech_support": "Tech support or computer help scam patterns detected",
            "kyc": "KYC/identity verification scam patterns detected",
            "suspicious_phone": "Contains suspicious phone number patterns"
        },
        "hi": {
            "urgency": "जल्दबाजी/धमकी भाषा का उपयोग करता है",
            "financial": "वित्तीय लेनदेन या भुगतान शब्द हैं",
            "authority": "अधिकारी (पुलिस, बैंक, सरकार) का रूप धारण",
            "prize": "दावा करता है कि आपने इनाम जीता है",
            "investment": "निवेश या घर से काम की पेशकश",
            "loan": "तुरंत लोन या क्रेडिट का वादा",
            "tech_support": "टेक सपोर्ट स्कैम का पता चला",
            "kyc": "KYC/पहचान सत्यापन स्कैम का पता चला",
        }
    }
    
    exp_lang = "hi" if language == "hi" else "en"
    exp_dict = explanations.get(exp_lang, explanations["en"])
    
    parts = []
    for cat in matched_categories:
        if cat in exp_dict:
            parts.append(exp_dict[cat])
    
    if not parts:
        return "No specific scam patterns detected."
    
    return " | ".join(parts)


# ============================================================================
# Main Entry Point (for testing)
# ============================================================================

if __name__ == "__main__":
    # Test with sample messages
    test_messages = [
        # English examples
        "Your OTP is 123456. UPI transaction pending. Verify now!",
        "Congratulations! You've won ₹5,00,000 lottery. Click to claim now!",
        "This is SBI Bank. Your account will be blocked in 24 hours. Update KYC immediately.",
        "This is Microsoft Tech Support. Your computer is infected. Call now.",
        "Your KYC is expired. Update now or account will be blocked.",
        
        # Hindi examples
        "आपका OTP 123456 है। UPI से ₹5000 कट गया। वेरीफाई करें।",
        "बधाई हो! आपने ₹10,00,000 जीते हैं। तुरंत क्लिक करें।",
        
        # Code-mixed example
        "Your account KYC update karna hai, warna band ho jayega. Click here: suspicious-link.com",
    ]
    
    for msg in test_messages:
        result = rule_based_score(msg)
        print(f"\n📝 Message: {msg[:60]}...")
        print(f"   Language: {result.detected_language}")
        print(f"   Score: {result.score}")
        print(f"   Categories: {result.matched_categories}")
        print(f"   Explanation: {get_explanation(result.matched_categories, result.detected_language)}")
