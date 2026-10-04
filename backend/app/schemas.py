from typing import List, Dict, Optional, Any, Union
from pydantic import BaseModel, Field, ConfigDict


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze for phishing threats", example="https://paypa1-security-verification.xyz/login.php")
    include_shap: bool = Field(default=True, description="Whether to include granular SHAP XAI attributions")


class BatchAnalysisRequest(BaseModel):
    urls: List[str] = Field(..., description="List of URLs to analyze in batch")


class FeatureAttribution(BaseModel):
    feature: str
    value: float
    shap_value: float
    direction: str
    importance: float
    description: str
    explanation: str


class HeuristicIndicator(BaseModel):
    id: str
    name: str
    severity: str  # "info", "warning", "critical"
    detected: bool
    details: str


class BrandDetectionResult(BaseModel):
    target_brand: Optional[str] = None
    is_spoofed: bool
    similarity_distance: Optional[int] = None
    technique: Optional[str] = None  # "exact_in_subdomain", "typosquatting", "path_injection", "none"
    assessment: str


class URLAnalysisResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    url: str
    domain: str
    registered_domain: str
    tld: str
    risk_score: float  # 0 to 100
    risk_level: str   # SAFE, LOW_RISK, SUSPICIOUS, HIGH_RISK, CRITICAL_PHISHING
    status_text: str
    color: str
    is_phishing: bool
    confidence: float
    model_breakdown: Dict[str, float]
    brand_analysis: BrandDetectionResult
    heuristics: List[HeuristicIndicator]
    recommended_action: str
    top_shap_attributions: List[FeatureAttribution]
    extracted_features: Dict[str, Union[float, int]]
    timestamp: str


class BatchSummary(BaseModel):
    total_scanned: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
    highest_risk_url: Optional[str] = None


class BatchAnalysisResponse(BaseModel):
    results: List[URLAnalysisResponse]
    summary: BatchSummary


class MetricItem(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    confusion_matrix: Dict[str, int]
    roc_curve: List[Dict[str, float]]


class ModelMetricsResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    primary_model: str
    test_samples_count: int
    primary_metrics: MetricItem
    model_comparison: Dict[str, MetricItem]
    global_importance: List[Dict[str, Any]]
