import joblib
import sys
import re
from urllib.parse import urlparse
from src.pipeline import clean_text 

def load_ai_brain():
    try:
        model = joblib.load("models/spam_model.pkl")
        vectorizer = joblib.load("models/vectorizer.pkl")
        return model, vectorizer
    except FileNotFoundError:
        print("❌ Error: Model assets missing! Run 'python run.py' first.")
        sys.exit(1)

def analyze_threat_metrics(message):
    """
    MASTER'S UPGRADE: Multi-Vector Threat Intelligence Engine.
    Evaluates character anomalies, brand domains, and deep intent risk flags.
    """
    risk_score = 0
    reasons = []
    
    msg_lower = message.lower()
    
    # 1. CHARACTER OBFUSCATION DETECTION
    # Look for single letters separated by dots or spaces (e.g., C.l.i.c.k or V_e_r_i_f_y)
    obfuscation_pattern = r'(?:\b[a-z][\s._]+){2,}[a-z]\b'
    if re.search(obfuscation_pattern, msg_lower):
        risk_score += 25
        reasons.append("Character Obfuscation Detected")

    # Normalize text to catch words hidden behind punctuation tricks
    msg_normalized = re.sub(r'(?<=\b[a-z])[\s._]+(?=[a-z]\b)', '', msg_lower)
    msg_normalized = re.sub(r'[^\w\s]', ' ', msg_normalized)
    msg_words = set(msg_normalized.split())

    # 2. EXTRACT URLS & DOMAINS
    url_pattern = r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)'
    links = re.findall(url_pattern, message)
    
    # EXPANDED BRAND DATABASE
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
        risk_score += 15  # Base risk for simply containing an outbound link
        
        for link in links:
            domain = link.split('/')[0].lower().strip('.,:;()')
            
            # Check suspicious top-level extensions or dash structures
            suspicious_extensions = ['.info', '.net', '.support', '-processing', '-secure', '-login', '-verify']
            if any(ext in domain for ext in suspicious_extensions):
                risk_score += 30
                if "Suspicious URL Structure" not in reasons:
                    reasons.append("Suspicious URL Structure")
            
            # Check for Explicit Brand Impersonation
            for brand, official_urls in trusted_brands.items():
                if brand in domain or brand in msg_normalized:
                    is_official = any(official in domain for official in official_urls)
                    if not is_official:
                        risk_score += 45
                        if "Brand Impersonation" not in reasons:
                            reasons.append(f"Brand Impersonation ({brand.upper()} Fake Link)")

    # 3. INTENT WORD CATEGORIES
    credential_tokens = {'login', 'credential', 'credentials', 'password', 'token', 'oauth', 'keys', 'verify', 'verification', 'confirm', 'validate', 'sync'}
    urgency_tokens = {'urgent', 'suspended', 'restricted', 'closure', 'suspend', 'expires', 'minutes', 'hours', 'midnight', 'action', 'delayed', 'immediately'}
    financial_tokens = {'cash', 'free', 'win', 'claim', 'prize', 'billing', 'wire', 'transfer', 'ledger', 'payment', 'fees', 'charges', 'refund', 'customs'}

    # Track semantic hits
    has_credential_request = any(word in msg_words for word in credential_tokens)
    has_urgency_language = any(word in msg_words for word in urgency_tokens)
    has_financial_risk = any(word in msg_words for word in financial_tokens)

    if has_credential_request:
        risk_score += 25
        reasons.append("Credential Request Pattern")
    if has_urgency_language:
        risk_score += 20
        reasons.append("Urgency Language")
    if has_financial_risk:
        risk_score += 20
        reasons.append("Financial / Billing Trigger")

    return min(risk_score, 100), reasons

def calculate_threat_tier(score):
    if score <= 20:
        return "LOW", "🍏"
    elif score <= 50:
        return "MEDIUM", "⚠️"
    elif score <= 80:
        return "HIGH", "🚨"
    else:
        return "CRITICAL", "🛑"

def evaluate_message(user_message, model, vectorizer):
    # 1. Fetch deep security matrix metrics
    security_score, threat_reasons = analyze_threat_metrics(user_message)
    
    # 2. Fetch standard AI probability core metrics
    transformed_vector = vectorizer.transform([user_message])
    ai_prediction = model.predict(transformed_vector)[0]
    ai_probabilities = model.predict_proba(transformed_vector)[0]
    ai_confidence = ai_probabilities[ai_prediction] * 100
    
    # 3. Harmonize machine learning core with rules engine
    # If AI flags text as spam, ensure a baseline security score
    if ai_prediction == 1 and security_score < 40:
        security_score = max(security_score, 45)
        if "AI Core Statistical Warning" not in threat_reasons:
            threat_reasons.append("AI Core Statistical Warning")

    tier, icon = calculate_threat_tier(security_score)
    return tier, icon, security_score, threat_reasons, ai_confidence

def live_gateway_tester():
    print("🧠 Loading Advanced Threat Assessment Gateway...")
    model, vectorizer = load_ai_brain()
    print("🛡️ Zero-Trust Engine Engaged with Granular Diagnostics!")
    print("----------------------------------------------------------------")
    
    while True:
        try:
            user_message = input("\n📝 Enter text message: ")
        except (KeyboardInterrupt, EOFError):
            break

        if user_message.lower() == 'exit':
            print("👋 Gateway offline.")
            break
            
        if not user_message.strip():
            continue
            
        tier, icon, score, reasons, ai_conf = evaluate_message(user_message, model, vectorizer)
        
        print("------------------------------------------------------------")
        print(f"THREAT LEVEL: {icon} [{tier}] (Score: {score}/100)")
        print(f"AI Core Match Confidence: {ai_conf:.2f}%")
        
        if reasons:
            print("Detected Risk Factors:")
            for reason in reasons:
                print(f"  + {reason}")
        else:
            print("  + No malicious vectors identified.")
        print("------------------------------------------------------------")

if __name__ == "__main__":
    live_gateway_tester()