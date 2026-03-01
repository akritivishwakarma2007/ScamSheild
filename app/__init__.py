# ScamShield Honeypot - AI-Powered Scam Detection System
# Package initialization

__version__ = "1.0.0"
__author__ = "Cracked Team - AI for Bharat Hackathon"

from app.analyzer import analyze_message
from app.rules import rule_based_score

__all__ = ["analyze_message", "rule_based_score"]
