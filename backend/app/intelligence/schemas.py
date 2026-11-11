from enum import Enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceSource(str, Enum):
    EMAIL_HEADER = "EMAIL_HEADER"
    EMAIL_BODY = "EMAIL_BODY"
    URL_EXTRACTION = "URL_EXTRACTION"
    DNS = "DNS"
    RDAP = "RDAP"
    GEOIP = "GEOIP"
    THREAT_INTEL = "THREAT_INTEL"
    GRAPH_CORRELATION = "GRAPH_CORRELATION"
    AI_INFERENCE = "AI_INFERENCE"
    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"


class ProviderMetadata(BaseModel):
    looked_up_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cache_hit: bool = False
    limitations: List[str] = Field(default_factory=list)


class GeoLocationInfo(ProviderMetadata):
    ip: str
    defanged_ip: str
    version: int = 4
    is_private: bool = False
    is_public: bool = True
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    hosting_provider: Optional[str] = None
    proxy_or_vpn: Optional[bool] = None
    is_datacenter: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_abuser: Optional[bool] = None
    provider: Optional[str] = None
    confidence: float = 0.0
    source: str = EvidenceSource.GEOIP.value
    status: str = "SUCCESS"  # SUCCESS, UNAVAILABLE, PRIVATE_IP, SPECIAL_USE_IP, RATE_LIMITED, AUTH_ERROR, TIMEOUT, ERROR


class DNSRecordEntry(BaseModel):
    domain: str
    record_type: str  # A, AAAA, MX, NS, TXT, CNAME
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None
    timestamp: str
    source: str = EvidenceSource.DNS.value
    status: str = "RESOLVED"  # RESOLVED, NXDOMAIN, TIMEOUT, ERROR


class DNSIntelligenceResult(ProviderMetadata):
    source: str = "DNS"
    domain: str
    records: List[DNSRecordEntry] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    mx_hosts: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    has_valid_mx: bool = False
    status: str = "SUCCESS"  # SUCCESS, NO_RECORDS, TIMEOUT, ERROR


class RDAPDomainInfo(ProviderMetadata):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    nameservers: List[str] = Field(default_factory=list)
    domain_status: List[str] = Field(default_factory=list)
    privacy_protected: bool = False
    raw_rdap_url: Optional[str] = None
    lookup_status: str = "SUCCESS"  # SUCCESS, UNAVAILABLE, RATE_LIMITED, ERROR
    source: str = EvidenceSource.RDAP.value


class DomainIntelligenceResult(BaseModel):
    domain: str
    registered_domain: str
    tld: str
    subdomain: Optional[str] = ""
    is_punycode: bool = False
    is_lookalike: bool = False
    entropy: float = 0.0
    suspicious_tld_flag: bool = False
    dns: Optional[DNSIntelligenceResult] = None
    rdap: Optional[RDAPDomainInfo] = None
    risk_signals: List[str] = Field(default_factory=list)
    source: str = "DOMAIN_ANALYSIS"


class ThreatReputationInfo(ProviderMetadata):
    context: Dict[str, Any] = Field(default_factory=dict)
    indicator: str
    indicator_type: str  # IP, DOMAIN, URL, HASH
    provider: str = "DeepTrace Intelligence Aggregator"
    reputation_score: float = 0.0  # 0 to 100
    malicious_votes: int = 0
    suspicious_votes: int = 0
    total_engines: int = 0
    blacklist_hits: List[str] = Field(default_factory=list)
    verdict: str = "UNKNOWN"  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    status: str = "AVAILABLE"  # AVAILABLE, UNAVAILABLE, RATE_LIMITED
    last_checked: str
    source: str = EvidenceSource.THREAT_INTEL.value


class OriginAssessmentResult(BaseModel):
    earliest_reliable_ip: Optional[str] = None
    defanged_earliest_reliable_ip: Optional[str] = None
    probable_origin_host: Optional[str] = None
    confidence: float = 0.0
    is_internal_hop: bool = False
    evidentiary_basis: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class InfrastructureIntelligence(BaseModel):
    mode: str = "offline"  # "live" or "offline"
    ip_intelligence: Dict[str, GeoLocationInfo] = Field(default_factory=dict)
    domain_intelligence: Dict[str, DomainIntelligenceResult] = Field(default_factory=dict)
    reputation_intelligence: Dict[str, ThreatReputationInfo] = Field(default_factory=dict)
    origin_assessment: OriginAssessmentResult
