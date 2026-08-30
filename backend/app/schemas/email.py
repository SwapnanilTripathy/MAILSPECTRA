from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str


class AddressEntity(BaseModel):
    display_name: str = ""
    address: str = ""
    domain: str = ""
    raw: str = ""


class AuthResultEntry(BaseModel):
    mechanism: str  # spf, dkim, dmarc, arc
    result: str  # pass, fail, softfail, neutral, none, permerror, temperror
    domain: Optional[str] = None
    selector: Optional[str] = None
    reason: Optional[str] = None
    details: Optional[str] = None


class AuthenticationSummary(BaseModel):
    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"
    arc_result: str = "none"
    auth_results_entries: List[AuthResultEntry] = Field(default_factory=list)
    raw_authentication_results: List[str] = Field(default_factory=list)
    raw_received_spf: List[str] = Field(default_factory=list)
    raw_dkim_signatures: List[str] = Field(default_factory=list)


class RelayHop(BaseModel):
    hop_index: int
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    defanged_from_ip: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    id_str: Optional[str] = None
    for_recipient: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_iso: Optional[str] = None
    delay_seconds: Optional[float] = None
    is_private_ip: bool = False
    is_public_ip: bool = False
    is_bogon_ip: bool = False
    is_origin_hop: bool = False
    raw_header: str = ""


class RelayChainSummary(BaseModel):
    total_hops: int = 0
    origin_ip: Optional[str] = None
    defanged_origin_ip: Optional[str] = None
    origin_host: Optional[str] = None
    final_destination_host: Optional[str] = None
    total_transmission_delay_seconds: Optional[float] = None
    hops: List[RelayHop] = Field(default_factory=list)


class ExtractedURL(BaseModel):
    url: str
    defanged_url: str
    scheme: str = ""
    host: str = ""
    domain: str = ""
    subdomain: str = ""
    registered_domain: str = ""
    tld: str = ""
    path: str = ""
    is_ip_host: bool = False
    is_shortener: bool = False
    source: str = "body"  # body_html, body_text, header


class ExtractedIP(BaseModel):
    ip: str
    defanged_ip: str
    version: int = 4
    is_private: bool = False
    is_public: bool = True
    is_loopback: bool = False
    is_multicast: bool = False
    is_bogon: bool = False
    source: str = "relay"  # relay, header, body


class AttachmentMetadata(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    extension: str = ""
    is_suspicious_extension: bool = False
    content_disposition: Optional[str] = None


class MIMEStructurePart(BaseModel):
    part_index: int
    content_type: str
    charset: Optional[str] = None
    content_disposition: Optional[str] = None
    filename: Optional[str] = None
    size_bytes: int = 0
    is_attachment: bool = False


class EmailMetadata(BaseModel):
    evidence_hashes: EvidenceHashes
    message_id: Optional[str] = None
    subject: str = ""
    date_raw: Optional[str] = None
    date_iso: Optional[str] = None
    from_sender: AddressEntity
    to_recipients: List[AddressEntity] = Field(default_factory=list)
    cc_recipients: List[AddressEntity] = Field(default_factory=list)
    bcc_recipients: List[AddressEntity] = Field(default_factory=list)
    reply_to: List[AddressEntity] = Field(default_factory=list)
    return_path: Optional[str] = None
    x_mailer: Optional[str] = None
    user_agent: Optional[str] = None
    content_type_header: Optional[str] = None
    all_headers: Dict[str, Any] = Field(default_factory=dict)
