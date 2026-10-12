import os
import json
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api", tags=["Metrics"])

METRICS_PATH = "ml/artifacts/metrics.json"
FEATURE_METADATA_PATH = "ml/artifacts/feature_metadata.json"


@router.get("/metrics")
async def get_model_metrics():
    """
    Return comprehensive model performance benchmarks, ROC-AUC, confusion matrices,
    and cross-model comparison statistics.
    """
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(status_code=404, detail="Metrics artifact not found. Please train models first.")
    
    with open(METRICS_PATH, "r") as f:
        metrics_data = json.load(f)
    
    return metrics_data


@router.get("/features")
async def get_feature_metadata():
    """
    Return feature engineering specifications, descriptions, and dataset statistics.
    """
    if not os.path.exists(FEATURE_METADATA_PATH):
        raise HTTPException(status_code=404, detail="Feature metadata not found.")
    
    with open(FEATURE_METADATA_PATH, "r") as f:
        metadata = json.load(f)
    
    return metadata
