import os
from datetime import datetime, timezone
import tldextract
from ml.src.feature_extractor import extract_features
from ml.src.explainer import PhishExplainer
from backend.app.services.heuristics import evaluate_heuristics
from backend.app.services.brand_detector import analyze_brand_spoofing

# Global singleton explainer instance
_explainer = None

def get_explainer() -> PhishExplainer:
    global _explainer
    if _explainer is None:
        _explainer = PhishExplainer(artifacts_dir="ml/artifacts")
        _explainer.load()
    return _explainer


def predict_and_explain(raw_url: str, include_shap: bool = True) -> dict:
    """
    Complete analysis pipeline: feature extraction, ensemble ML inference,
    SHAP XAI feature attribution, heuristics evaluation, brand detection,
    and mitigation recommendations.
    """
    explainer = get_explainer()
    url = raw_url.strip()

    # 1. Feature extraction
    features = extract_features(url)

    # 2. ML Prediction & SHAP explanation
    explanation = explainer.explain_url_features(features, top_k=10 if include_shap else 0)

    # 3. Domain details
    ext = tldextract.extract(url)
    domain = ext.domain.lower() if ext.domain else "unknown"
    suffix = ext.suffix.lower() if ext.suffix else ""
    registered_domain = f"{domain}.{suffix}" if suffix else domain

    # 4. Brand spoofing analysis
    brand_analysis = analyze_brand_spoofing(url)

    # 5. Rule heuristics
    heuristics = evaluate_heuristics(features, url)

    # 6. Actionable recommendations
    risk_level = explanation["risk_level"]
    if risk_level == "CRITICAL_PHISHING":
        recommended_action = "CRITICAL ACTION: Block domain immediately at firewall/DNS. Mark email/message as hostile phishing attempt. Never enter passwords or personal data."
    elif risk_level == "HIGH_RISK":
        recommended_action = "HIGH ALERT: Do not authenticate or download attachments. Confirm origin out-of-band with official provider before interacting."
    elif risk_level == "SUSPICIOUS":
        recommended_action = "CAUTION: Anomalous URL parameters or obfuscation indicators identified. Verify domain authenticity in address bar."
    elif risk_level == "LOW_RISK":
        recommended_action = "LOW RISK: Primarily benign characteristics observed. Practice standard cyber hygiene."
    else:
        recommended_action = "SAFE TO ACCESS: Cryptographic, structural, and domain reputation metrics align with legitimate services."

    timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "url": url,
        "domain": domain,
        "registered_domain": registered_domain,
        "tld": suffix,
        "risk_score": explanation["risk_score_percent"],
        "risk_level": risk_level,
        "status_text": explanation["status_text"],
        "color": explanation["color"],
        "is_phishing": explanation["risk_score_percent"] >= 50.0,
        "confidence": round(max(explanation["phishing_probability"], explanation["legitimate_probability"]) * 100, 1),
        "model_breakdown": explanation["model_breakdown"],
        "brand_analysis": brand_analysis,
        "heuristics": heuristics,
        "recommended_action": recommended_action,
        "top_shap_attributions": explanation["top_attributions"] if include_shap else [],
        "extracted_features": features,
        "timestamp": timestamp
    }
