from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphNodeType(str, Enum):
    EMAIL = "EMAIL"
    SENDER = "SENDER"
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    MAIL_SERVER = "MAIL_SERVER"
    ASN = "ASN"
    LOCATION = "LOCATION"
    CAMPAIGN = "CAMPAIGN"
    CASE = "CASE"


class GraphEdgeType(str, Enum):
    SENT_FROM = "SENT_FROM"
    CONTAINS_URL = "CONTAINS_URL"
    TRANSMITTED_VIA = "TRANSMITTED_VIA"
    RESOLVES_TO = "RESOLVES_TO"
    HOSTED_ON_ASN = "HOSTED_ON_ASN"
    LOCATED_IN = "LOCATED_IN"
    PART_OF_CAMPAIGN = "PART_OF_CAMPAIGN"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"


class ThreatGraphNode(BaseModel):
    id: str
    node_type: str
    label: str
    source: str = "ANALYSIS"
    confidence: float = 1.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class ThreatGraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    confidence: float = 1.0
    evidence: str = ""
    timestamp: Optional[str] = None


class ThreatGraphData(BaseModel):
    total_nodes: int = 0
    total_edges: int = 0
    connected_components_count: int = 0
    density: float = 0.0
    nodes: List[ThreatGraphNode] = Field(default_factory=list)
    edges: List[ThreatGraphEdge] = Field(default_factory=list)


class CampaignCorrelationMatch(BaseModel):
    related_case_id: str
    related_case_filename: str = ""
    related_case_subject: str = ""
    related_case_classification: str = ""
    correlation_score: float = 0.0  # 0.0 to 1.0
    shared_indicators: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)


class CampaignEntity(BaseModel):
    campaign_id: str
    name: str
    primary_threat_type: str
    confidence: float = 0.8
    member_case_ids: List[str] = Field(default_factory=list)
    shared_infrastructure: Dict[str, List[str]] = Field(default_factory=dict)
    threat_summary: str = ""


class AttributionSupportResult(BaseModel):
    assessment: str  # SPOOFED_IDENTITY, LIKELY_COMPROMISED_ACCOUNT, ANONYMIZED_INFRASTRUCTURE, SHARED_CAMPAIGN_INFRASTRUCTURE, DIRECT_MALICIOUS_INFRASTRUCTURE, INSUFFICIENT_EVIDENCE
    confidence: float = 0.0
    evidentiary_basis: List[str] = Field(default_factory=list)
    mitigating_factors: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
