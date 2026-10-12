import os
from datetime import datetime, timezone
from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["Health"])

MODEL_ARTIFACT_PATH = "ml/artifacts/phishguard_ensemble.joblib"


@router.get("/health")
async def health_check():
    """
    Check operational status of PhishGuard backend and verify ML artifact readiness.
    """
    model_ready = os.path.exists(MODEL_ARTIFACT_PATH)
    
    return {
        "status": "online",
        "service": "PhishGuard-AI Core Service",
        "version": "1.0.0",
        "model_loaded": model_ready,
        "engine": "LightGBM + XGBoost + Random Forest Ensemble with SHAP XAI",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
