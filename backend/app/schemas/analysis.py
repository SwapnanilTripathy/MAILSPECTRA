from backend.app.core.versions import PARSER_VERSION
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.graph.schemas import (
    AttributionSupportResult,
    CampaignCorrelationMatch,
    CampaignEntity,
    ThreatGraphData,
)
from backend.app.intelligence.schemas import (
    GeoLocationInfo,
    InfrastructureIntelligence,
    OriginAssessmentResult,
)
from backend.app.ml.schemas import (
    FeatureExtractionSummary,
    MLPredictionResult,
    RiskAssessmentResult,
    SecurityIndicator,
    SHAPExplanation,
)
from backend.app.schemas.email import (
    AttachmentMetadata,
    AuthenticationSummary,
    EmailMetadata,
    EvidenceHashes,
    ExtractedIP,
    ExtractedURL,
    MIMEStructurePart,
    RelayChainSummary,
)


class BodyContent(BaseModel):
    text_plain: str = ""
    text_html: str = ""
    text_plain_length: int = 0
    text_html_length: int = 0
    has_html: bool = False
    has_plain_text: bool = False


class ThreatIndicator(BaseModel):
    category: str  # IDENTITY, HEADER, URL, CONTENT, ATTACHMENT, AUTHENTICATION, BEHAVIOR
    feature: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    observed_value: Any = None


class InitialThreatAssessment(BaseModel):
    risk_score: float = 0.0  # 0 to 100
    classification: str = "BENIGN"  # BENIGN, SUSPICIOUS, PHISHING, SPOOFED, etc.
    confidence: float = 1.0
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    explanation: str = ""


class ArtifactMetadata(BaseModel):
    artifact_id: str
    sha256: str
    size_bytes: int
    filename: str
    ingested_at: str
    actor: str
    parser_version: str = PARSER_VERSION


class EvidenceObservation(BaseModel):
    observation_id: str
    observation_type: str
    value: str
    source_artifact_id: str
    source_location: Dict[str, Any]
    observed_at: str
    verification_status: str = "OBSERVED_UNVERIFIED"
    parser_version: str = PARSER_VERSION


class EmailAnalysisResponse(BaseModel):
    schema_version: str = "1.1"
    artifact: Optional[ArtifactMetadata] = None
    observations: List[EvidenceObservation] = Field(default_factory=list)
    evidence_manifest: Dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    privacy_redaction_applied: bool = False
    case_id: str
    analyzed_at: str
    filename: Optional[str] = "uploaded.eml"
    file_size_bytes: int
    evidence_hashes: EvidenceHashes
    metadata: EmailMetadata
    authentication: AuthenticationSummary
    relay_chain: RelayChainSummary
    urls: List[ExtractedURL] = Field(default_factory=list)
    ips: List[ExtractedIP] = Field(default_factory=list)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    mime_structure: List[MIMEStructurePart] = Field(default_factory=list)
    body: BodyContent
    threat_assessment: InitialThreatAssessment
    
    # Phase 2 AI & Explainability Extensions
    ai_inference: Optional[MLPredictionResult] = None
    risk_assessment: Optional[RiskAssessmentResult] = None
    shap_explanation: Optional[SHAPExplanation] = None
    feature_summary: Optional[FeatureExtractionSummary] = None
    observed_evidence: List[SecurityIndicator] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    # NLP & Content Intelligence Signals
    content_intelligence: Optional[Any] = None

    # Real-Time Security Alerting
    security_alert: Optional[Any] = None

    # Phase 3 Forensic Intelligence, Threat Graph & Campaign Correlation Extensions
    infrastructure_intelligence: Optional[InfrastructureIntelligence] = None
    geolocation: Optional[Dict[str, GeoLocationInfo]] = None
    origin_assessment: Optional[OriginAssessmentResult] = None
    threat_graph: Optional[ThreatGraphData] = None
    campaign_correlations: List[CampaignCorrelationMatch] = Field(default_factory=list)
    active_campaign: Optional[CampaignEntity] = None
    attribution_support: Optional[AttributionSupportResult] = None


