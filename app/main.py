"""
ScamShield Honeypot - FastAPI Backend
=====================================
Main application entry point for the ScamShield scam detection API.

Author: Cracked Team - AI for Bharat Hackathon
Team Leader: Lakshya Kumar Singh
"""

import os
import logging
import uuid
import asyncio
import json
import re
from contextlib import asynccontextmanager
from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import app modules
from app.analyzer import analyze_message
from app.utils import validate_message
from app.prompts import SYSTEM_PROMPT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Application Lifecycle
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler - startup and shutdown events."""
    logger.info("🚀 ScamShield Honeypot API Starting...")
    logger.info(f"📦 Ollama Model: {os.getenv('OLLAMA_MODEL', 'qwen2.5:14b')}")
    logger.info(f"🔗 Ollama URL: {os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')}")
    logger.info("✅ ScamShield API Ready!")
    yield
    logger.info("👋 ScamShield API Shutting Down...")


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="ScamShield Honeypot API",
    description="AI-Powered Scam Detection & Prevention System for India",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ============================================================================
# Request/Response Models
# ============================================================================

class AnalyzeRequest(BaseModel):
    """Request model for message analysis."""
    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The suspicious message to analyze",
        examples=["Your OTP is 123456. UPI transaction pending."]
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Your OTP is 847293. UPI transaction of ₹10,000 pending. Verify now."
            }
        }


class AnalyzeResponse(BaseModel):
    """Response model for analysis results."""
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100%")
    scam_type: str = Field(..., description="Type of scam detected")
    explanation: str = Field(..., description="Detailed explanation")
    high_risk: bool = Field(..., description="Whether message is high risk (≥75%)")
    suggested_safe_reply: Optional[str] = Field(None, description="Safe reply for honeypot mode")
    language: str = Field(..., description="Detected language code")
    safety_message: str = Field(..., description="Safety warning message")
    
class Config:
        json_schema_extra = {
            "example": {
                "risk_score": 85,
                "scam_type": "UPI Phishing",
                "explanation": "This message contains multiple red flags...",
                "high_risk": True,
                "suggested_safe_reply": "Can you send official bank email?",
                "language": "en",
                "safety_message": "⚠️ Do NOT share OTP. Report to 1930 / cybercrime.gov.in"
            }
        }


# ============================================================================
# Honeypot Chat - Session Management
# ============================================================================

# In-memory sessions (for demo; use Redis / database in production)
chat_sessions: Dict[str, List[Dict]] = {}  # session_id → [{"role": "user"/"assistant", "content": "..."}]


class ChatMessage(BaseModel):
    """Request model for honeypot chat."""
    session_id: Optional[str] = None
    message: str = Field(..., description="What user pastes (scammer's message)")
    initial_analysis: bool = Field(default=False, description="Whether to run initial analysis")


# ============================================================================
# Honeypot Chat - Extraction Function
# ============================================================================

async def extract_info(history: List[Dict]) -> Dict:
    """
    Extract scammer information from conversation history.
    
    Args:
        history: List of message dictionaries with 'role' and 'content'
        
    Returns:
        Dictionary with extracted info: upi_id, phone, bank, amount
    """
    # Build conversation text for extraction
    conversation = "\n".join([
        f"{m['role'].capitalize()}: {m['content']}" 
        for m in history[-10:]  # Last 10 messages
    ])
    
    extraction_prompt = f"""From this conversation, extract ONLY the following information as JSON:
{{
  "upi_id": null or string (UPI ID like xyz@upi),
  "phone": null or string (Indian phone number),
  "bank": null or string (bank name mentioned),
  "amount": null or number (amount in INR)
}}

If information is not found, use null. Be precise and only extract what is explicitly mentioned.

Conversation:
{conversation}

Respond with JSON only, no other text:"""

    try:
        import ollama
        model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
        
        response = await asyncio.to_thread(
            ollama.generate,
            model=model_name,
            prompt=extraction_prompt,
            options={"temperature": 0.3, "num_predict": 200, "format": "json"}
        )
        
        # Parse the JSON response
        try:
            extracted = json.loads(response["response"].strip())
            return {
                "upi_id": extracted.get("upi_id"),
                "phone": extracted.get("phone"),
                "bank": extracted.get("bank"),
                "amount": extracted.get("amount")
            }
        except json.JSONDecodeError:
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response["response"])
            if json_match:
                try:
                    extracted = json.loads(json_match.group())
                    return {
                        "upi_id": extracted.get("upi_id"),
                        "phone": extracted.get("phone"),
                        "bank": extracted.get("bank"),
                        "amount": extracted.get("amount")
                    }
                except json.JSONDecodeError:
                    pass
            return {}
            
    except Exception as e:
        logger.error(f"❌ Extraction error: {str(e)}")
        return {}


# ============================================================================
# Honeypot Chat - Ramesh Persona Prompt
# ============================================================================

HONEYPOT_SYSTEM_PROMPT = """You are Ramesh, a simple Indian villager who is slightly naive but helpful. 
You respond in a friendly, casual manner using simple Hindi-English mix (Hinglish).
Keep responses SHORT - 1-2 sentences max.
You are cautious about sharing personal details but want to help.

Guidelines:
- Use informal language like "arre bhai", "yaar", "thik hai"
- Don't reveal too much personal information
- Ask for clarification when confused
- Be polite but not overly suspicious
- Sometimes pretend to be busy or distracted
- Never use JSON in responses - just plain text"""


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
async def root():
    """Serve the main HTML page."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return """
    <html>
        <head><title>ScamShield Honeypot</title></head>
        <body>
            <h1>ScamShield Honeypot 🛡️</h1>
            <p>API is running. Visit <a href="/docs">/docs</a> for API documentation.</p>
        </body>
    </html>
    """


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "ScamShield Honeypot",
        "version": "1.0.0",
        "model": os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
    }


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_suspicious_message(request: AnalyzeRequest):
    """
    Analyze a suspicious message for potential scam indicators.
    
    Uses hybrid detection:
    - Rule-based keyword matching (40% weight)
    - LLM-based intent analysis via Ollama (60% weight)
    
    Returns risk score, scam type, explanation, and safe reply suggestions.
    """
    try:
        # Validate message
        is_valid, error_msg = validate_message(request.message)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
        
        logger.info(f"📨 Analyzing message: {request.message[:100]}...")
        
        # Perform hybrid analysis
        result = await analyze_message(request.message)
        
        logger.info(f"✅ Analysis complete: {result['risk_score']}% risk - {result['scam_type']}")
        
        return AnalyzeResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Analysis error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}. Please ensure Ollama is running."
        )


@app.get("/model/status", tags=["Model"])
async def model_status():
    """Check Ollama model status."""
    try:
        import ollama
        model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
        
        # Try to get model info
        try:
            model_info = ollama.show(model_name)
            return {
                "status": "loaded",
                "model": model_name,
                "info": model_info
            }
        except Exception:
            return {
                "status": "not_loaded",
                "model": model_name,
                "message": "Model not found. Run: ollama pull " + model_name
            }
    except ImportError:
        return {
            "status": "error",
            "message": "Ollama client not installed"
        }


@app.post("/chat", tags=["Honeypot"])
async def honeypot_chat(msg: ChatMessage):
    """
    Honeypot chat endpoint for interacting with scammers.
    
    This endpoint allows Law Enforcement to engage with scammers in a conversation
    to gather evidence and extract information. The AI responds as "Ramesh", 
    a naive but helpful Indian villager.
    
    - Creates new session if no session_id provided
    - Maintains conversation history for context
    - Extracts UPI ID, phone, bank, amount from conversation
    - Returns session_id for continuing conversation
    """
    global chat_sessions
    
    # Create or retrieve session
    if not msg.session_id:
        session_id = str(uuid.uuid4())
        chat_sessions[session_id] = []
    else:
        session_id = msg.session_id
        if session_id not in chat_sessions:
            raise HTTPException(status_code=404, detail="Session not found")

    history = chat_sessions[session_id]

    # Add user's (scammer's) message to history
    history.append({"role": "user", "content": msg.message})

    # Build full prompt for Ramesh persona
    full_prompt = f"{HONEYPOT_SYSTEM_PROMPT}\n\nCurrent conversation:\n"
    for m in history[-12:]:  # last 12 messages to avoid token limit
        role = "User" if m["role"] == "user" else "You"
        full_prompt += f"{role}: {m['content']}\n"
    full_prompt += "\nReply as Ramesh (short message only, no JSON):"

    try:
        import ollama
        model_name = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
        
        response = await asyncio.to_thread(
            ollama.generate,
            model=model_name,
            prompt=full_prompt,
            options={"temperature": 0.7, "num_predict": 300}
        )
        reply = response["response"].strip()
    except Exception as e:
        logger.error(f"❌ Ollama error: {str(e)}")
        reply = "Arre bhai... thoda network slow hai... 1 min ruk jao"

    # Add assistant reply to history
    history.append({"role": "assistant", "content": reply})

    # Extract information from conversation (in parallel)
    extraction = await extract_info(history)

    # Clean old sessions (keep last 100)
    if len(chat_sessions) > 100:
        # Remove oldest sessions
        old_sessions = list(chat_sessions.keys())[:len(chat_sessions) - 100]
        for old_session in old_sessions:
            del chat_sessions[old_session]

    return {
        "session_id": session_id,
        "reply": reply,
        "history": history[-8:],  # send recent part to frontend
        "extracted": extraction or {}
    }


@app.get("/chat/sessions", tags=["Honeypot"])
async def list_sessions():
    """List all active honeypot sessions."""
    return {
        "total_sessions": len(chat_sessions),
        "session_ids": list(chat_sessions.keys())[:10]  # First 10 for preview
    }


@app.delete("/chat/sessions/{session_id}", tags=["Honeypot"])
async def delete_session(session_id: str):
    """Delete a specific honeypot session."""
    if session_id in chat_sessions:
        del chat_sessions[session_id]
        return {"status": "deleted", "session_id": session_id}
    raise HTTPException(status_code=404, detail="Session not found")


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(404)
async def not_found(request, exc):
    """Custom 404 handler."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Endpoint not found. Visit /docs for API documentation."}
    )


@app.exception_handler(500)
async def internal_error(request, exc):
    """Custom 500 handler."""
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please check Ollama is running."}
    )


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    debug = os.getenv("DEBUG", "true").lower() == "true"
    
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
