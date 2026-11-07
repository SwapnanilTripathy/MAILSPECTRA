from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatClass(str, Enum):
    LEGITIMATE = "LEGITIMATE"
    PHISHING = "PHISHING"
    BUSINESS_EMAIL_COMPROMISE = "BUSINESS_EMAIL_COMPROMISE"
    IMPERSONATION = "IMPERSONATION"
    FRAUD = "FRAUD"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    SUSPICIOUS = "SUSPICIOUS"


class IndicatorCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    IDENTITY = "IDENTITY"
    CONTENT = "CONTENT"
    URL = "URL"
    HEADER = "HEADER"
    ATTACHMENT = "ATTACHMENT"
    BEHAVIOR = "BEHAVIOR"


class IndicatorSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class SecurityIndicator(BaseModel):
    indicator: str
    category: str
    severity: str
    observed: bool = True
    evidence: str = ""
    weight: float = 0.0
    details: Optional[Dict[str, Any]] = None


ThreatIndicator = SecurityIndicator


class SHAPFeatureContribution(BaseModel):
    feature: str
    feature_name: str
    value: float
    contribution: float
    direction: str  # "increases_risk" or "decreases_risk"
    description: str


class SHAPExplanation(BaseModel):
    predicted_class: str
    base_value: float = 0.0
    top_features: List[SHAPFeatureContribution] = Field(default_factory=list)
    explanation_summary: str = ""
    method: str = "TreeExplainer/LinearExplainer"


class MLPredictionResult(BaseModel):
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float] = Field(default_factory=dict)
    is_model_available: bool = True
    model_version: str = "1.0.0"
    model_type: str = "LogisticRegression + TF-IDF"
    feature_version: str = "structured-v1"
    confidence_definition: str = "Predicted class probability; uncalibrated demonstration model"
    limitations: List[str] = Field(default_factory=list)


class RiskAssessmentResult(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score from 0.0 (clean) to 100.0 (critical threat)")
    severity: str = "INFORMATIONAL"
    classification: str = "LEGITIMATE"
    model_confidence: float = 1.0
    evidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    indicators: List[SecurityIndicator] = Field(default_factory=list)
    methodology: str = "Hybrid ML Probability + Forensic Weighted Indicator Aggregation"


class FeatureExtractionSummary(BaseModel):
    total_features_extracted: int = 0
    text_feature_count: int = 0
    structured_feature_count: int = 0
    key_extracted_signals: Dict[str, Any] = Field(default_factory=dict)


class AIThreatAnalysis(BaseModel):
    ai_inference: MLPredictionResult
    risk_assessment: RiskAssessmentResult
    shap_explanation: SHAPExplanation
    feature_summary: FeatureExtractionSummary
    limitations: List[str] = Field(default_factory=list)
