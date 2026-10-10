from typing import List
from fastapi import APIRouter, HTTPException
from backend.app.schemas import (
    URLAnalysisRequest, URLAnalysisResponse,
    BatchAnalysisRequest, BatchAnalysisResponse, BatchSummary
)
from backend.app.services.predictor import predict_and_explain

router = APIRouter(prefix="/api", tags=["Analysis"])

# Curated sample URLs for quick evaluation in the UI
SAMPLE_URLS = [
    {
        "category": "Typosquatting Phishing",
        "label": "Spoofed PayPal Security Alert",
        "url": "http://paypa1-security-verification.xyz/login.php?user=victim",
        "expected": "CRITICAL_PHISHING"
    },
    {
        "category": "Subdomain Masquerading",
        "label": "Fake Apple ID Subdomain",
        "url": "http://appleid.apple.com.verify-account-security.cfd/signin",
        "expected": "CRITICAL_PHISHING"
    },
    {
        "category": "IP & Port Evasion",
        "label": "Raw IP Host with Port & Banking Path",
        "url": "http://192.168.1.105:8080/chase/webscr/login.php",
        "expected": "CRITICAL_PHISHING"
    },
    {
        "category": "Legitimate Platform",
        "label": "Official GitHub Repository",
        "url": "https://github.com/torvalds/linux",
        "expected": "SAFE"
    },
    {
        "category": "Legitimate Enterprise",
        "label": "Wikipedia Knowledge Base",
        "url": "https://en.wikipedia.org/wiki/Phishing",
        "expected": "SAFE"
    },
    {
        "category": "Legitimate Banking",
        "label": "Chase Official Portal",
        "url": "https://www.chase.com/personal/banking",
        "expected": "SAFE"
    }
]


@router.post("/analyze", response_model=URLAnalysisResponse)
async def analyze_single_url(payload: URLAnalysisRequest):
    """
    Inspect a single URL through the PhishGuard ensemble ML pipeline and SHAP explainability.
    """
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    
    try:
        result = predict_and_explain(url, include_shap=payload.include_shap)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@router.post("/batch-analyze", response_model=BatchAnalysisResponse)
async def analyze_batch_urls(payload: BatchAnalysisRequest):
    """
    Process multiple URLs in batch mode and compute triage metrics.
    """
    if not payload.urls:
        raise HTTPException(status_code=400, detail="URL list cannot be empty.")
    
    if len(payload.urls) > 100:
        raise HTTPException(status_code=400, detail="Batch size limited to 100 URLs per request.")

    results = []
    safe_cnt = 0
    suspicious_cnt = 0
    phishing_cnt = 0
    max_risk = -1.0
    highest_risk_url = None

    for raw_url in payload.urls:
        url = raw_url.strip()
        if not url:
            continue
        try:
            # For speed in batch mode, exclude SHAP computation unless requested
            res = predict_and_explain(url, include_shap=False)
            results.append(res)

            if res["risk_level"] in ["CRITICAL_PHISHING", "HIGH_RISK"]:
                phishing_cnt += 1
            elif res["risk_level"] == "SUSPICIOUS":
                suspicious_cnt += 1
            else:
                safe_cnt += 1

            if res["risk_score"] > max_risk:
                max_risk = res["risk_score"]
                highest_risk_url = res["url"]

        except Exception as e:
            continue

    summary = BatchSummary(
        total_scanned=len(results),
        safe_count=safe_cnt,
        suspicious_count=suspicious_cnt,
        phishing_count=phishing_cnt,
        highest_risk_url=highest_risk_url
    )

    return BatchAnalysisResponse(results=results, summary=summary)


@router.get("/samples")
async def get_sample_urls():
    """
    Provide curated test URLs across threat and legitimate categories.
    """
    return {"samples": SAMPLE_URLS}
