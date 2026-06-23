import os
from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import joblib
import re
from src.pipeline import clean_text

app = FastAPI(title="SMS Threat Assessment Gateway")

# Point to our HTML templates folder
templates = Jinja2Templates(directory="templates")

# Load our AI core models
try:
    model = joblib.load("models/spam_model.pkl")
    vectorizer = joblib.load("models/vectorizer.pkl")
except FileNotFoundError:
    print("❌ Critical Error: Train the model first using 'python run.py'")

def analyze_threat_metrics(message):
    risk_score = 0
    reasons = []
    msg_lower = message.lower()
    
    # 1. Character Obfuscation Check
    obfuscation_pattern = r'(?:\b[a-z][\s._]+){2,}[a-z]\b'
    if re.search(obfuscation_pattern, msg_lower):
        risk_score += 25
        reasons.append("Character Obfuscation Detected")

    # Normalize Text
    msg_normalized = re.sub(r'(?<=\b[a-z])[\s._]+(?=[a-z]\b)', '', msg_lower)
    msg_normalized = re.sub(r'[^\w\s]', ' ', msg_normalized)
    msg_words = set(msg_normalized.split())

    # 2. Link Extraction & Brand Analysis
    url_pattern = r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)'
    links = re.findall(url_pattern, message)
    
    trusted_brands = {
        'microsoft': ['microsoft.com', 'teams.microsoft.com', 'live.com', 'office.com'],
        'dhl': ['dhl.com', 'dhl.fr', 'logistics.dhl'],
        'tax': ['gouv.fr', 'gov.uk', 'irs.gov'],
        'github': ['github.com', 'github.io'],
        'aws': ['amazon.com', 'amazonaws.com', 'aws.amazon.com'],
        'fedex': ['fedex.com', 'fedex.fr'],
        'paypal': ['paypal.com', 'paypal.fr'],
        'netflix': ['netflix.com'],
        'google': ['google.com', 'gmail.com', 'accounts.google.com']
    }

    if links:
        risk_score += 15
        for link in links:
            domain = link.split('/')[0].lower().strip('.,:;()')
            suspicious_extensions = ['.info', '.net', '.support', '-processing', '-secure', '-login', '-verify']
            if any(ext in domain for ext in suspicious_extensions):
                risk_score += 30
                if "Suspicious URL Structure" not in reasons:
                    reasons.append("Suspicious URL Structure")
            
            for brand, official_urls in trusted_brands.items():
                if brand in domain or brand in msg_normalized:
                    is_official = any(official in domain for official in official_urls)
                    if not is_official:
                        risk_score += 45
                        if "Brand Impersonation" not in reasons:
                            reasons.append(f"Brand Impersonation ({brand.upper()} Fake Link)")

    # 3. Intent Keywords Check
    credential_tokens = {'login', 'credential', 'credentials', 'password', 'token', 'oauth', 'keys', 'verify', 'verification', 'confirm', 'validate', 'sync'}
    urgency_tokens = {'urgent', 'suspended', 'restricted', 'closure', 'suspend', 'expires', 'minutes', 'hours', 'midnight', 'action', 'delayed', 'immediately'}
    financial_tokens = {'cash', 'free', 'win', 'claim', 'prize', 'billing', 'wire', 'transfer', 'ledger', 'payment', 'fees', 'charges', 'refund', 'customs'}

    if any(word in msg_words for word in credential_tokens):
        risk_score += 25
        reasons.append("Credential Request Pattern")
    if any(word in msg_words for word in urgency_tokens):
        risk_score += 20
        reasons.append("Urgency Language")
    if any(word in msg_words for word in financial_tokens):
        risk_score += 20
        reasons.append("Financial / Billing Trigger")

    return min(risk_score, 100), reasons

def get_threat_tier(score):
    if score <= 20: return "LOW", "🟢", "bg-green-100 text-green-800 border-green-300", "Do NOT interact with unverified elements, but message looks safe."
    elif score <= 50: return "MEDIUM", "🟡", "bg-yellow-100 text-yellow-800 border-yellow-300", "Exercise caution. Verify the sender identity directly."
    elif score <= 80: return "HIGH", "🟠", "bg-orange-100 text-orange-800 border-orange-300", "Highly suspicious. Avoid clicking any embedded links."
    else: return "CRITICAL", "🔴", "bg-red-100 text-red-800 border-red-300", "High probability of Phishing! Delete message and block sender immediately."

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serves the front page entry viewport."""
    return templates.TemplateResponse("index.html", {"request": request, "analyzed": False})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_sms(request: Request, message: str = Form(...)):
    """Handles incoming post analysis form submissions."""
    if not message.strip():
        return templates.TemplateResponse("index.html", {"request": request, "analyzed": False})

    # Execute Hybrid Engine Processing
    score, reasons = analyze_threat_metrics(message)
    
    transformed_vector = vectorizer.transform([message])
    ai_pred = model.predict(transformed_vector)[0]
    ai_probs = model.predict_proba(transformed_vector)[0]
    ai_conf = ai_probs[ai_pred] * 100
    
    if ai_pred == 1 and score < 40:
        score = max(score, 45)
        reasons.append("AI Core Statistical Warning")

    tier, icon, style_classes, recommendation = get_threat_tier(score)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "analyzed": True,
        "message": message,
        "tier": tier,
        "icon": icon,
        "score": score,
        "reasons": reasons,
        "ai_conf": f"{ai_conf:.2f}%",
        "style": style_classes,
        "recommendation": recommendation
    })