/**
 * ScamShield Honeypot - Frontend JavaScript
 * =========================================
 * AI-Powered Scam Detection & Prevention System for India
 * 
 * Author: Cracked Team - AI for Bharat Hackathon
 * Team Leader: Lakshya Kumar Singh
 */

// ============================================================================
// Configuration
// ============================================================================

const API_ENDPOINT = '/analyze';
const CHAT_ENDPOINT = '/chat';
const ANALYZE_BTN_ID = 'analyze-btn';
const MESSAGE_INPUT_ID = 'message-input';
const RESULTS_SECTION_ID = 'results';
const LOADING_ID = 'loading';
const ERROR_ID = 'error';
const CHAR_COUNT_ID = 'char-count';

// ============================================================================
// DOM Elements
// ============================================================================

let analyzeBtn;
let messageInput;
let resultsSection;
let loadingSection;
let errorSection;
let charCountSpan;

// Honeypot elements
let currentSessionId = null;
let honeypotChatSection;
let chatInput;
let sendChatButton;
let chatMessagesContainer;
let startHoneypotButton;

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initializeElements();
    attachEventListeners();
    console.log('🛡️ ScamShield Honeypot initialized');
});

function initializeElements() {
    analyzeBtn = document.getElementById(ANALYZE_BTN_ID);
    messageInput = document.getElementById(MESSAGE_INPUT_ID);
    resultsSection = document.getElementById(RESULTS_SECTION_ID);
    loadingSection = document.getElementById(LOADING_ID);
    errorSection = document.getElementById(ERROR_ID);
    charCountSpan = document.getElementById(CHAR_COUNT_ID);
    
    // Honeypot elements
    honeypotChatSection = document.getElementById('honeypot-chat');
    chatInput = document.getElementById('chat-input');
    sendChatButton = document.getElementById('send-chat');
    chatMessagesContainer = document.getElementById('chat-messages');
    startHoneypotButton = document.getElementById('start-honeypot-btn');
}

function attachEventListeners() {
    // Analyze button click
    analyzeBtn.addEventListener('click', handleAnalyze);
    
    // Enter key to analyze (Ctrl+Enter)
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.ctrlKey) {
            handleAnalyze();
        }
    });
    
    // Character count update
    messageInput.addEventListener('input', updateCharCount);
    
    // Reset button (if exists)
    const resetBtn = document.getElementById('reset-btn');
    if (resetBtn) {
        resetBtn.addEventListener('click', handleReset);
    }
    
    // Copy reply button (if exists)
    const copyBtn = document.getElementById('copy-reply-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', handleCopyReply);
    }
    
    // Honeypot chat event listeners
    if (startHoneypotButton) {
        startHoneypotButton.addEventListener('click', startHoneypot);
    }
    
    if (sendChatButton) {
        sendChatButton.addEventListener('click', sendChatMessage);
    }
    
    if (chatInput) {
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendChatMessage();
            }
        });
    }
}

// ============================================================================
// Character Count
// ============================================================================

function updateCharCount() {
    const count = messageInput.value.length;
    charCountSpan.textContent = count;
    
    // Visual feedback when approaching limit
    if (count > 4500) {
        charCountSpan.style.color = '#f44336';
    } else if (count > 4000) {
        charCountSpan.style.color = '#ff9800';
    } else {
        charCountSpan.style.color = '';
    }
}

// ============================================================================
// Analyze Message
// ============================================================================

async function handleAnalyze() {
    const message = messageInput.value.trim();
    
    // Validation
    if (!message) {
        showError('Please enter a message to analyze.');
        return;
    }
    
    if (message.length < 5) {
        showError('Message is too short. Please enter a more complete message.');
        return;
    }
    
    // Show loading, hide previous results/error
    hideError();
    hideResults();
    showLoading();
    disableAnalyzeButton();
    
    try {
        const result = await analyzeMessage(message);
        hideLoading();
        displayResults(result);
    } catch (error) {
        hideLoading();
        
        // Handle specific error types
        if (error.message.includes('Ollama')) {
            showError('Ollama is not running. Please start Ollama and try again.');
        } else if (error.message.includes('Network') || error.message.includes('fetch')) {
            showError('Network error. Please check your connection and try again.');
        } else {
            showError(error.message || 'An error occurred. Please try again.');
        }
        
        enableAnalyzeButton();
    }
}

async function analyzeMessage(message) {
    const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message })
    });
    
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server error: ${response.status}`);
    }
    
    return await response.json();
}

// ============================================================================
// Display Results
// ============================================================================

function displayResults(result) {
    // Update risk gauge
    updateRiskGauge(result.risk_score);
    
    // Update scam type
    document.getElementById('scam-type').textContent = result.scam_type;
    
    // Update explanation
    document.getElementById('explanation').textContent = result.explanation;
    
    // Update safety message
    document.getElementById('safety-text').textContent = result.safety_message;
    
    // Handle high risk alert and safe reply
    const highRiskAlert = document.getElementById('high-risk-alert');
    const safeReplyText = document.getElementById('safe-reply-text');
    
    if (result.high_risk) {
        highRiskAlert.classList.remove('hidden');
        safeReplyText.textContent = result.suggested_safe_reply || 'No safe reply available.';
    } else {
        highRiskAlert.classList.add('hidden');
    }
    
    // Show results
    showResults();
    enableAnalyzeButton();
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    console.log('✅ Analysis complete:', result);
}

function updateRiskGauge(score) {
    const gaugeScore = document.getElementById('gauge-score');
    const gaugeArc = document.getElementById('gauge-arc');
    const riskBadge = document.getElementById('risk-badge');
    
    // Update score text
    gaugeScore.textContent = `${score}%`;
    
    // Calculate arc length (max is ~251)
    const arcLength = (score / 100) * 251;
    gaugeArc.setAttribute('stroke-dasharray', `${arcLength} 251`);
    
    // Determine color based on score
    let color;
    let badgeClass;
    let badgeText;
    let badgeIcon;
    
    if (score < 25) {
        color = '#4caf50';
        badgeClass = 'low-risk';
        badgeText = 'Low Risk';
        badgeIcon = '✅';
    } else if (score < 50) {
        color = '#8bc34a';
        badgeClass = 'low-risk';
        badgeText = 'Low Risk';
        badgeIcon = '✅';
    } else if (score < 75) {
        color = '#ff9800';
        badgeClass = 'medium-risk';
        badgeText = 'Medium Risk';
        badgeIcon = '⚠️';
    } else if (score < 90) {
        color = '#f44336';
        badgeClass = 'high-risk';
        badgeText = 'High Risk';
        badgeIcon = '🚨';
    } else {
        color = '#d32f2f';
        badgeClass = 'critical-risk';
        badgeText = 'Critical Risk';
        badgeIcon = '🚨';
    }
    
    // Update arc color
    gaugeArc.setAttribute('stroke', color);
    
    // Update badge
    riskBadge.className = `risk-badge ${badgeClass}`;
    riskBadge.innerHTML = `<span class="risk-icon">${badgeIcon}</span><span class="risk-text">${badgeText}</span>`;
}

// ============================================================================
// Copy Safe Reply
// ============================================================================

function handleCopyReply() {
    const safeReplyText = document.getElementById('safe-reply-text').textContent;
    const copyBtn = document.getElementById('copy-reply-btn');
    
    if (!safeReplyText || safeReplyText === '-') {
        return;
    }
    
    // Copy to clipboard
    navigator.clipboard.writeText(safeReplyText).then(() => {
        // Visual feedback
        copyBtn.textContent = '✅ Copied!';
        copyBtn.classList.add('copied');
        
        // Reset after 2 seconds
        setTimeout(() => {
            copyBtn.textContent = '📋 Copy';
            copyBtn.classList.remove('copied');
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = safeReplyText;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        copyBtn.textContent = '✅ Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => {
            copyBtn.textContent = '📋 Copy';
            copyBtn.classList.remove('copied');
        }, 2000);
    });
}

// ============================================================================
// Reset
// ============================================================================

function handleReset() {
    // Clear input
    messageInput.value = '';
    updateCharCount();
    
    // Hide results
    hideResults();
    
    // Focus on input
    messageInput.focus();
}

// ============================================================================
// UI State Management
// ============================================================================

function showLoading() {
    loadingSection.classList.remove('hidden');
    analyzeBtn.disabled = true;
}

function hideLoading() {
    loadingSection.classList.add('hidden');
}

function showResults() {
    resultsSection.classList.remove('hidden');
}

function hideResults() {
    resultsSection.classList.add('hidden');
}

function showError(message) {
    const errorMessage = document.getElementById('error-message');
    errorMessage.textContent = message;
    errorSection.classList.remove('hidden');
}

function hideError() {
    errorSection.classList.add('hidden');
}

function disableAnalyzeButton() {
    analyzeBtn.disabled = true;
    analyzeBtn.querySelector('.btn-text').textContent = 'Analyzing...';
}

function enableAnalyzeButton() {
    analyzeBtn.disabled = false;
    analyzeBtn.querySelector('.btn-text').textContent = 'Analyze Message';
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Format a number with commas
 */
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ============================================================================
// Keyboard Shortcuts
// ============================================================================

document.addEventListener('keydown', (e) => {
    // Ctrl+Enter to analyze
    if (e.ctrlKey && e.key === 'Enter') {
        if (!analyzeBtn.disabled) {
            handleAnalyze();
        }
    }
    
    // Escape to reset
    if (e.key === 'Escape') {
        if (!resultsSection.classList.contains('hidden')) {
            handleReset();
        }
    }
});

// ============================================================================
// Service Worker Registration (for PWA capability)
// ============================================================================

if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        // Service worker can be added later for offline capability
        console.log('📱 PWA support available');
    });
}

// ============================================================================
// Analytics (placeholder for future)
// ============================================================================

function trackEvent(eventName, data) {
    // Placeholder for analytics tracking
    console.log('📊 Event:', eventName, data);
}

// Track analysis events
const originalAnalyze = handleAnalyze;
handleAnalyze = async function(...args) {
    const startTime = Date.now();
    try {
        await originalAnalyze.apply(this, args);
        trackEvent('analysis_complete', {
            duration: Date.now() - startTime,
            success: true
        });
    } catch (error) {
        trackEvent('analysis_error', {
            duration: Date.now() - startTime,
            error: error.message
        });
        throw error;
    }
};

// ============================================================================
// Export for testing (if needed)
// ============================================================================

window.ScamShield = {
    handleAnalyze,
    analyzeMessage,
    displayResults,
    handleReset,
    handleCopyReply,
    startHoneypot,
    sendChatMessage,
    addChatMessage
};

// ============================================================================
// Honeypot Chat Functions
// ============================================================================

/**
 * Start the honeypot chat mode
 * Called after first analysis if high_risk
 */
function startHoneypot() {
    if (honeypotChatSection) {
        honeypotChatSection.classList.remove('hidden');
        addChatMessage("System", "Honeypot started. Paste scammer messages below. I'll reply as confused uncle.");
        
        // Disable start button after clicking
        if (startHoneypotButton) {
            startHoneypotButton.disabled = true;
            startHoneypotButton.textContent = "Chat Active";
        }
        
        // Focus on chat input
        if (chatInput) {
            chatInput.focus();
        }
        
        // Scroll to honeypot section
        honeypotChatSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

/**
 * Send a chat message to the honeypot backend
 */
async function sendChatMessage() {
    if (!chatInput) return;
    
    const text = chatInput.value.trim();
    if (!text) return;

    // Add user (scammer) message to chat
    addChatMessage("Scammer", text);
    chatInput.value = '';

    // Show loading state
    const sendBtn = document.getElementById('send-chat');
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.textContent = '...';
    }

    try {
        const res = await fetch(CHAT_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: currentSessionId,
                message: text
            })
        });
        
        if (!res.ok) {
            throw new Error(`Server error: ${res.status}`);
        }
        
        const data = await res.json();

        // Set session ID for future messages
        if (!currentSessionId && data.session_id) {
            currentSessionId = data.session_id;
        }

        // Add Ramesh (AI) response to chat
        addChatMessage("Ramesh (you)", data.reply);

        // Update extracted info display
        if (data.extracted && Object.keys(data.extracted).length > 0) {
            updateExtractedInfo(data.extracted);
        }
        
    } catch (err) {
        console.error('Chat error:', err);
        addChatMessage("System", "Error... try again.");
    } finally {
        // Reset button state
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.textContent = 'Send';
        }
    }
}

/**
 * Add a message to the honeypot chat display
 */
function addChatMessage(sender, text) {
    if (!chatMessagesContainer) return;
    
    const div = document.createElement('div');
    // Determine message class based on sender
    const messageClass = sender.toLowerCase().includes('ramesh') || sender.toLowerCase().includes('you') 
        ? 'agent' 
        : sender.toLowerCase().includes('system') 
            ? 'system'
            : 'user';
    
    div.className = `chat-message ${messageClass}`;
    div.innerHTML = `<strong>${sender}:</strong> ${text}`;
    chatMessagesContainer.appendChild(div);
    
    // Scroll to bottom
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
}

/**
 * Update the extracted information display
 */
function updateExtractedInfo(extracted) {
    const extractedInfoDiv = document.getElementById('extracted-info');
    if (!extractedInfoDiv) return;
    
    // Update individual fields if they exist
    const upiIdEl = document.getElementById('upi-id');
    const phoneEl = document.getElementById('phone');
    const bankEl = document.getElementById('bank');
    const amountEl = document.getElementById('amount');
    
    if (upiIdEl) upiIdEl.textContent = extracted.upi_id || '-';
    if (phoneEl) phoneEl.textContent = extracted.phone || '-';
    if (bankEl) bankEl.textContent = extracted.bank || '-';
    if (amountEl) amountEl.textContent = extracted.amount ? `₹${extracted.amount}` : '-';
    
    // Also update the raw JSON display
    const extractedDataDiv = document.getElementById('extracted-data');
    if (extractedDataDiv) {
        extractedDataDiv.innerHTML = `
            <span class="extracted-item">UPI ID: <span id="upi-id">${extracted.upi_id || '-'}</span></span>
            <span class="extracted-item">Phone: <span id="phone">${extracted.phone || '-'}</span></span>
            <span class="extracted-item">Bank: <span id="bank">${extracted.bank || '-'}</span></span>
            <span class="extracted-item">Amount: <span id="amount">${extracted.amount ? '₹' + extracted.amount : '-'}</span></span>
        `;
    }
}

/**
 * Reset honeypot session (called when reset button is clicked)
 */
function resetHoneypot() {
    currentSessionId = null;
    if (chatMessagesContainer) {
        chatMessagesContainer.innerHTML = '';
    }
    if (startHoneypotButton) {
        startHoneypotButton.disabled = false;
        startHoneypotButton.textContent = 'Start Chat';
    }
}
