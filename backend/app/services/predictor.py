import os
from datetime import datetime, timezone
import tldextract
from ml.src.feature_extractor import extract_features
from ml.src.explainer import PhishExplainer
from backend.app.services.heuristics import evaluate_heuristics
from backend.app.services.brand_detector import analyze_brand_spoofing

# Global singleton explainer instance
_explainer = None

KNOWN_MAJOR_DOMAINS = {
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "wikipedia.org", "youtube.com", "stackoverflow.com", "nytimes.com",
    "bbc.com", "bbc.co.uk", "netflix.com", "spotify.com", "reddit.com", "linkedin.com",
    "cloudflare.com", "fastapi.tiangolo.com", "python.org", "pypi.org",
    "rust-lang.org", "crates.io", "react.dev", "steampowered.com",
    "mozilla.org", "arxiv.org", "docker.com", "ycombinator.com",
    "chase.com", "bankofamerica.com", "target.com", "walmart.com", "medium.com"
}

def get_explainer() -> PhishExplainer:
    global _explainer
    if _explainer is None:
        _explainer = PhishExplainer(artifacts_dir="ml/artifacts")
        _explainer.load()
    return _explainer


def classify_threat_level(risk_score: float) -> tuple[str, str, str]:
    """Map normalized threat risk percentage to SOC operational categories."""
    if risk_score >= 85.0:
        return "CRITICAL_PHISHING", "Severe Phishing Threat Detected", "rose"
    elif risk_score >= 65.0:
        return "HIGH_RISK", "Probable Phishing Campaign", "orange"
    elif risk_score >= 45.0:
        return "SUSPICIOUS", "Suspicious URL Structure", "amber"
    elif risk_score >= 20.0:
        return "LOW_RISK", "Low Risk / Likely Legitimate", "blue"
    else:
        return "SAFE", "Verified Benign Pattern", "emerald"


def predict_and_explain(raw_url: str, include_shap: bool = True) -> dict:
    """
    Complete cybersecurity analysis pipeline:
    - 34-feature extraction (lexical, structural, cryptographic, entropy)
    - Ensemble ML inference (Soft Voting: LightGBM, XGBoost, Random Forest)
    - SHAP XAI local attribution (TreeExplainer with background baseline)
    - Brand impersonation & typosquatting detection
    - Rule-based heuristics evaluation
    - Hybrid defense-in-depth threat scoring & mitigation recommendations
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

    # 6. Hybrid Cyber Defense Threat Fusion
    risk_score = float(explanation["risk_score_percent"])

    # High-confidence attack overrides
    if brand_analysis.get("is_spoofed"):
        technique = brand_analysis.get("technique")
        if technique in ["subdomain_spoofing", "typosquatting", "tld_brand_hijack"]:
            risk_score = max(risk_score, 88.0)
        else:
            risk_score = max(risk_score, 72.0)

    if features.get("has_ip") == 1:
        risk_score = max(risk_score, 85.0)

    if features.get("has_punycode") == 1:
        risk_score = max(risk_score, 82.0)

    if features.get("suspicious_tld") == 1 and features.get("sensitive_keywords_count", 0) >= 1:
        risk_score = max(risk_score, 78.0)

    # Verified high-reputation domain protection (no spoofing, standard HTTPS)
    if registered_domain in KNOWN_MAJOR_DOMAINS and not brand_analysis.get("is_spoofed") and features.get("has_ip") == 0:
        risk_score = min(risk_score, 35.0)

    risk_score = round(risk_score, 1)
    risk_level, status_text, color = classify_threat_level(risk_score)

    # 7. Actionable recommendations
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
        "risk_score": risk_score,
        "risk_level": risk_level,
        "status_text": status_text,
        "color": color,
        "is_phishing": risk_score >= 50.0,
        "confidence": round(max(explanation["phishing_probability"], explanation["legitimate_probability"]) * 100, 1),
        "model_breakdown": explanation["model_breakdown"],
        "brand_analysis": brand_analysis,
        "heuristics": heuristics,
        "recommended_action": recommended_action,
        "top_shap_attributions": explanation["top_attributions"] if include_shap else [],
        "extracted_features": features,
        "timestamp": timestamp
    }
