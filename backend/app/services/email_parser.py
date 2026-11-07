import email
from email import policy
from email.header import decode_header
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import tldextract
from backend.app.core.config import settings
_TLD = tldextract.TLDExtract(suffix_list_urls=())

from backend.app.core.logging import logger
from backend.app.schemas.analysis import (
    BodyContent,
    EmailAnalysisResponse,
    InitialThreatAssessment,
    ThreatIndicator,
)
from backend.app.schemas.email import (
    AddressEntity,
    AttachmentMetadata,
    AuthenticationSummary,
    AuthResultEntry,
    EmailMetadata,
    EvidenceHashes,
    ExtractedIP,
    ExtractedURL,
    MIMEStructurePart,
    RelayChainSummary,
    RelayHop,
)
from backend.app.utils.crypto import calculate_hashes, calculate_text_hash, defang_ip, defang_url
from backend.app.utils.network import classify_ip, extract_ips_from_text, is_valid_ip


URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
    re.IGNORECASE,
)

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".js", ".jse",
    ".wsf", ".wsh", ".pif", ".iso", ".img", ".vhd", ".docm", ".xlsm", ".pptm",
    ".dll", ".jar", ".cpl", ".msi", ".msp"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"
}

URGENCY_KEYWORDS = [
    "urgent", "immediate action", "account suspended", "unauthorized access",
    "password expired", "verify your identity", "security alert", "wire transfer",
    "payment overdue", "invoice attached", "update payment", "confirm credentials",
    "click here immediately", "action required"
]


class EmailForensicParser:
    """Enterprise-grade MIME forensic parser and observable extractor for .eml files."""

    def __init__(self, raw_bytes: bytes, filename: Optional[str] = "uploaded.eml"):
        self.raw_bytes = raw_bytes
        self.filename = filename or "uploaded.eml"
        self.file_size = len(raw_bytes)
        self.evidence_hashes = calculate_hashes(raw_bytes)
        self.msg: Optional[EmailMessage] = None
        self._parse_raw_message()

    def _parse_raw_message(self) -> None:
        """Parse raw bytes into Python EmailMessage object with default policy."""
        try:
            self.msg = email.message_from_bytes(self.raw_bytes, policy=policy.default)
        except Exception as e:
            logger.warning("Default parsing policy failed: %s; using compatibility policy", type(e).__name__)
            self.msg = email.message_from_bytes(self.raw_bytes, policy=policy.compat32)

    def _decode_header_str(self, header_value: Any) -> str:
        """Safely decode RFC 2047 encoded email header."""
        if not header_value:
            return ""
        if not isinstance(header_value, str):
            header_value = str(header_value)
        try:
            decoded_parts = decode_header(header_value)
            result = []
            for text, charset in decoded_parts:
                if isinstance(text, bytes):
                    enc = charset or "utf-8"
                    try:
                        result.append(text.decode(enc, errors="replace"))
                    except (LookupError, UnicodeDecodeError):
                        result.append(text.decode("latin-1", errors="replace"))
                else:
                    result.append(str(text))
            return "".join(result).strip()
        except Exception:
            return str(header_value).strip()

    def _parse_address_entity(self, raw_header: Optional[str]) -> AddressEntity:
        """Parse display name and email address from header string."""
        if not raw_header:
            return AddressEntity()
        decoded = self._decode_header_str(raw_header)
        name, addr = parseaddr(decoded)
        domain = addr.split("@")[-1].lower() if "@" in addr else ""
        return AddressEntity(
            display_name=name.strip(),
            address=addr.strip().lower(),
            domain=domain,
            raw=decoded,
        )

    def _parse_address_list(self, raw_header: Optional[str]) -> List[AddressEntity]:
        """Parse comma-separated address list into AddressEntity items."""
        if not raw_header:
            return []
        decoded = self._decode_header_str(raw_header)
        addresses = getaddresses([decoded])
        entities = []
        for name, addr in addresses:
            if addr or name:
                domain = addr.split("@")[-1].lower() if "@" in addr else ""
                entities.append(
                    AddressEntity(
                        display_name=name.strip(),
                        address=addr.strip().lower(),
                        domain=domain,
                        raw=f"{name} <{addr}>" if name else addr,
                    )
                )
        return entities

    def extract_metadata(self) -> EmailMetadata:
        """Extract all essential email headers and metadata."""
        if not self.msg:
            return EmailMetadata(
                evidence_hashes=EvidenceHashes(**self.evidence_hashes),
                from_sender=AddressEntity(),
            )

        # Date formatting
        date_raw = self.msg.get("Date")
        date_iso = None
        if date_raw:
            try:
                dt = parsedate_to_datetime(date_raw)
                date_iso = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                date_iso = None

        # Return-Path sanitization
        return_path_raw = self.msg.get("Return-Path")
        return_path = None
        if return_path_raw:
            rp_match = re.search(r"<([^>]+)>", str(return_path_raw))
            return_path = rp_match.group(1).strip().lower() if rp_match else str(return_path_raw).strip("<> ").lower()

        # Collect all raw headers
        all_headers_dict: Dict[str, Any] = {}
        for k, v in self.msg.items():
            k_lower = k.lower()
            decoded_val = self._decode_header_str(str(v))
            if k_lower in all_headers_dict:
                if isinstance(all_headers_dict[k_lower], list):
                    all_headers_dict[k_lower].append(decoded_val)
                else:
                    all_headers_dict[k_lower] = [all_headers_dict[k_lower], decoded_val]
            else:
                all_headers_dict[k_lower] = decoded_val

        return EmailMetadata(
            evidence_hashes=EvidenceHashes(**self.evidence_hashes),
            message_id=self._decode_header_str(self.msg.get("Message-ID")),
            subject=self._decode_header_str(self.msg.get("Subject")),
            date_raw=self._decode_header_str(date_raw),
            date_iso=date_iso,
            from_sender=self._parse_address_entity(self.msg.get("From")),
            to_recipients=self._parse_address_list(", ".join(self.msg.get_all("To", []))),
            cc_recipients=self._parse_address_list(", ".join(self.msg.get_all("Cc", []))),
            bcc_recipients=self._parse_address_list(self.msg.get("Bcc")),
            reply_to=self._parse_address_list(self.msg.get("Reply-To")),
            return_path=return_path,
            x_mailer=self._decode_header_str(self.msg.get("X-Mailer")),
            user_agent=self._decode_header_str(self.msg.get("User-Agent")),
            content_type_header=self.msg.get_content_type() if hasattr(self.msg, "get_content_type") else self.msg.get("Content-Type"),
            all_headers=all_headers_dict,
            raw_headers=[{"name":k,"value":v} for k,v in self.msg.raw_items()],
        )

    def extract_authentication(self) -> AuthenticationSummary:
        """Parse SPF, DKIM, DMARC, ARC results from Authentication-Results and related headers."""
        if not self.msg:
            return AuthenticationSummary()

        auth_headers = self.msg.get_all("Authentication-Results", [])
        received_spf_headers = self.msg.get_all("Received-SPF", [])
        dkim_sig_headers = self.msg.get_all("DKIM-Signature", [])

        spf_result = "none"
        dkim_result = "none"
        dmarc_result = "none"
        arc_result = "none"
        auth_entries: List[AuthResultEntry] = []

        # Parse Authentication-Results headers
        for raw_auth in auth_headers:
            decoded_auth = self._decode_header_str(str(raw_auth))
            
            # SPF check
            spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b(?:\s+\(([^)]+)\))?", decoded_auth, re.IGNORECASE)
            if spf_match:
                res = spf_match.group(1).lower()
                spf_result = res
                reason = spf_match.group(2) if spf_match.group(2) else ""
                auth_entries.append(AuthResultEntry(mechanism="spf", result=res, reason=reason, details=decoded_auth))

            # DKIM check
            dkim_matches = re.finditer(r"\bdkim=(pass|fail|none|temperror|permerror)\b(?:\s+\(([^)]+)\))?(?:\s+header\.[di]=([^\s;]+))?", decoded_auth, re.IGNORECASE)
            for dm in dkim_matches:
                res = dm.group(1).lower()
                dkim_result = res
                reason = dm.group(2) if dm.group(2) else ""
                domain = dm.group(3) if dm.group(3) else ""
                auth_entries.append(AuthResultEntry(mechanism="dkim", result=res, domain=domain, reason=reason, details=decoded_auth))

            # DMARC check
            dmarc_match = re.search(r"\bdmarc=(pass|fail|none|temperror|permerror)\b(?:\s+\(([^)]+)\))?(?:\s+header\.from=([^\s;]+))?", decoded_auth, re.IGNORECASE)
            if dmarc_match:
                res = dmarc_match.group(1).lower()
                dmarc_result = res
                reason = dmarc_match.group(2) if dmarc_match.group(2) else ""
                domain = dmarc_match.group(3) if dmarc_match.group(3) else ""
                auth_entries.append(AuthResultEntry(mechanism="dmarc", result=res, domain=domain, reason=reason, details=decoded_auth))

            # ARC check
            arc_match = re.search(r"\barc=(pass|fail|none)\b", decoded_auth, re.IGNORECASE)
            if arc_match:
                arc_result = arc_match.group(1).lower()
                auth_entries.append(AuthResultEntry(mechanism="arc", result=arc_result, details=decoded_auth))

        # Check Received-SPF headers if not found
        for raw_spf in received_spf_headers:
            decoded_spf = self._decode_header_str(str(raw_spf))
            match = re.match(r"^(pass|fail|softfail|neutral|none|temperror|permerror)\b", decoded_spf, re.IGNORECASE)
            if match and spf_result == "none":
                spf_result = match.group(1).lower()
                auth_entries.append(AuthResultEntry(mechanism="spf", result=spf_result, details=decoded_spf))

        # Check DKIM-Signature presence
        if dkim_result == "none" and dkim_sig_headers:
            dkim_result = "present_unverified"

        has_auth_evidence = bool(auth_headers or received_spf_headers or dkim_sig_headers)
        availability_status = "AVAILABLE" if has_auth_evidence else "Not available in supplied evidence"

        return AuthenticationSummary(
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            arc_result=arc_result,
            availability_status=availability_status,
            auth_results_entries=auth_entries,
            raw_authentication_results=[self._decode_header_str(str(h)) for h in auth_headers],
            raw_received_spf=[self._decode_header_str(str(h)) for h in received_spf_headers],
            raw_dkim_signatures=[self._decode_header_str(str(h)) for h in dkim_sig_headers],
        )

    def extract_relay_chain(self) -> RelayChainSummary:
        """Reconstruct hop-by-hop relay transmission path from Received headers."""
        if not self.msg:
            return RelayChainSummary(
                relay_availability_status="Relay path unavailable — no usable Received headers were present in the supplied artifact."
            )

        raw_received = self.msg.get_all("Received", [])
        if not raw_received:
            return RelayChainSummary(
                relay_availability_status="Relay path unavailable — no usable Received headers were present in the supplied artifact."
            )


        # Received headers are recorded top-to-bottom (newest first).
        # Chronological transmission sequence is bottom-to-top.
        chronological_headers = list(reversed(raw_received))
        hops: List[RelayHop] = []
        prev_dt: Optional[datetime] = None

        for idx, r_header in enumerate(chronological_headers, start=1):
            header_str = self._decode_header_str(str(r_header))
            header_clean = " ".join(header_str.split())

            # Parsing components from Received string
            # Format typically: from <from_host> (<rdns> [<ip>]) by <by_host> with <proto> id <id> for <for>; <date>
            from_host = None
            from_ip = None
            by_host = None
            proto = None
            id_val = None
            for_val = None
            timestamp_raw = None
            timestamp_iso = None
            delay_sec = None
            anomalies = []

            # Extract date (everything after last semicolon)
            if ";" in header_clean:
                parts = header_clean.rsplit(";", 1)
                date_part = parts[1].strip()
                timestamp_raw = date_part
                try:
                    dt = parsedate_to_datetime(date_part)
                    if dt.tzinfo is None:
                        raise ValueError("Missing timezone")
                    timestamp_iso = dt.astimezone(timezone.utc).isoformat()
                    if prev_dt:
                        delay = (dt - prev_dt).total_seconds()
                        delay_sec = delay
                        if delay < 0 or delay > 86400:
                            anomalies.append("Timestamp sequence is negative or exceeds one day; supplied headers may be inaccurate")
                    prev_dt = dt
                except Exception:
                    anomalies.append("Unparseable timestamp or missing timezone")
                    prev_dt = None
                main_part = parts[0]
            else:
                main_part = header_clean

            # From section parsing: from <from_host> (<rdns> [<ip>])
            from_match = re.search(r"\bfrom\s+(.*?)(?=\s+by\b|\s+with\b|\s+id\b|\s+for\b|$)", main_part, re.IGNORECASE)
            if from_match:
                from_str = from_match.group(1).strip()
                from_host = from_str.split()[0] if from_str else None
                from_ips = extract_ips_from_text(from_str)
                if from_ips:
                    from_ip = from_ips[0]

            # By section parsing: by <by_host> (<rdns> [<ip>])
            by_match = re.search(r"\bby\s+(.*?)(?=\s+with\b|\s+id\b|\s+for\b|$)", main_part, re.IGNORECASE)
            if by_match:
                by_str = by_match.group(1).strip()
                by_host = by_str.split()[0] if by_str else None

            # With regex
            with_match = re.search(r"\bwith\s+([^\s;]+)", main_part, re.IGNORECASE)
            if with_match:
                proto = with_match.group(1)

            # ID regex
            id_match = re.search(r"\bid\s+([^\s;]+)", main_part, re.IGNORECASE)
            if id_match:
                id_val = id_match.group(1)

            # For regex
            for_match = re.search(r"\bfor\s+<([^>]+)>|\bfor\s+([^\s;]+)", main_part, re.IGNORECASE)
            if for_match:
                for_val = for_match.group(1) or for_match.group(2)

            ip_class = classify_ip(from_ip) if from_ip else {}
            is_priv = ip_class.get("is_private", False)
            is_pub = ip_class.get("is_public", False)
            is_bog = ip_class.get("is_bogon", False)

            hops.append(
                RelayHop(
                    hop_index=idx,
                    anomalies=anomalies,
                    trust_status="CONFIGURED_RECEIVER_CLAIM" if by_host in settings.TRUSTED_RECEIVERS else "UNTRUSTED_SUPPLIED_HEADER",
                    from_host=from_host,
                    from_ip=from_ip,
                    defanged_from_ip=defang_ip(from_ip) if from_ip else None,
                    by_host=by_host,
                    with_protocol=proto,
                    id_str=id_val,
                    for_recipient=for_val,
                    timestamp_raw=timestamp_raw,
                    timestamp_iso=timestamp_iso,
                    delay_seconds=delay_sec,
                    is_private_ip=is_priv,
                    is_public_ip=is_pub,
                    is_bogon_ip=is_bog,
                    is_origin_hop=(idx == 1),
                    raw_header=header_str,
                )
            )

        # Identify Origin IP (prefer first public IP in chain, else first hop IP)
        origin_ip = None
        origin_host = None
        for hop in hops:
            if hop.from_ip and hop.is_public_ip:
                origin_ip = hop.from_ip
                origin_host = hop.from_host
                break
        if not origin_ip and hops and hops[0].from_ip:
            origin_ip = hops[0].from_ip
            origin_host = hops[0].from_host

        final_dest = hops[-1].by_host if hops else None
        total_delay = sum(h.delay_seconds for h in hops if h.delay_seconds is not None) if hops else 0.0

        return RelayChainSummary(
            total_hops=len(hops),
            origin_ip=origin_ip,
            defanged_origin_ip=defang_ip(origin_ip) if origin_ip else None,
            origin_host=origin_host,
            final_destination_host=final_dest,
            total_transmission_delay_seconds=total_delay,
            hops=hops,
        )

    def extract_body_and_structure(self) -> Tuple[BodyContent, List[MIMEStructurePart], List[AttachmentMetadata]]:
        """Walk MIME parts and extract plain text, HTML body, MIME parts, and attachments."""
        text_plain_parts: List[str] = []
        text_html_parts: List[str] = []
        structure_parts: List[MIMEStructurePart] = []
        attachments: List[AttachmentMetadata] = []

        if not self.msg:
            return BodyContent(), [], []

        part_idx = 1
        for part in self.msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            if filename:
                filename = self._decode_header_str(filename)

            payload_bytes = b""
            try:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload_bytes = payload
                elif isinstance(payload, str):
                    payload_bytes = payload.encode("utf-8", errors="replace")
            except Exception:
                payload_bytes = b""

            is_attach = "attachment" in cdisp.lower() or bool(filename)

            structure_parts.append(
                MIMEStructurePart(
                    part_index=part_idx,
                    content_type=ctype,
                    charset=part.get_content_charset(),
                    content_disposition=cdisp or None,
                    filename=filename,
                    size_bytes=len(payload_bytes),
                    is_attachment=is_attach,
                )
            )
            part_idx += 1

            # Process attachment
            if is_attach and (filename or payload_bytes):
                att_name = filename or f"attachment_{part_idx}.bin"
                ext = ("." + att_name.rsplit(".", 1)[-1].lower()) if "." in att_name else ""
                hashes = calculate_hashes(payload_bytes)
                is_suspicious = ext in SUSPICIOUS_EXTENSIONS

                attachments.append(
                    AttachmentMetadata(
                        mime_part_index=part_idx - 1,
                        filename=att_name,
                        content_type=ctype,
                        size_bytes=len(payload_bytes),
                        md5=hashes["md5"],
                        sha1=hashes["sha1"],
                        sha256=hashes["sha256"],
                        extension=ext,
                        signature_type="PE_EXECUTABLE" if payload_bytes.startswith(b"MZ") else "ZIP_CONTAINER" if payload_bytes.startswith(b"PK\x03\x04") else "PDF" if payload_bytes.startswith(b"%PDF") else "UNKNOWN",
                        double_extension=len(att_name.split(".")) > 2,
                        is_suspicious_extension=is_suspicious,
                        content_disposition=cdisp or None,
                    )
                )
                continue

            # Process body text
            if ctype == "text/plain" and not is_attach:
                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded_text = payload_bytes.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    decoded_text = payload_bytes.decode("latin-1", errors="replace")
                text_plain_parts.append(decoded_text)

            elif ctype == "text/html" and not is_attach:
                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded_html = payload_bytes.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    decoded_html = payload_bytes.decode("latin-1", errors="replace")
                text_html_parts.append(decoded_html)

        full_plain = "\n".join(text_plain_parts).strip()
        full_html = "\n".join(text_html_parts).strip()

        body = BodyContent(
            text_plain=full_plain,
            text_html=full_html,
            text_plain_length=len(full_plain),
            text_html_length=len(full_html),
            has_html=bool(full_html),
            has_plain_text=bool(full_plain),
        )

        return body, structure_parts, attachments

    def extract_urls(self, body: BodyContent) -> List[ExtractedURL]:
        """Extract, parse, normalize, and defang all URLs from HTML and plain text bodies."""
        seen_urls: Set[str] = set()
        extracted: List[ExtractedURL] = []

        def process_url(raw_url: str, source: str) -> None:
            clean_url = raw_url.strip(" <>\"'()[]")
            if not clean_url:
                return
            if clean_url in seen_urls:
                for item in extracted:
                    if item.url == clean_url and source not in item.source_locations:
                        item.source_locations.append(source)
                return
            if clean_url.startswith(("mailto:", "javascript:", "tel:", "#")):
                return
            if not clean_url.startswith(("http://", "https://", "ftp://")):
                clean_url = "http://" + clean_url

            seen_urls.add(clean_url)

            parsed = urlparse(clean_url)
            host = (parsed.hostname or "").lower()
            ext = _TLD(clean_url)
            reg_domain = ext.registered_domain
            tld = ext.suffix
            subdomain = ext.subdomain

            is_ip = is_valid_ip(host)
            is_short = reg_domain in KNOWN_SHORTENERS or host in KNOWN_SHORTENERS

            extracted.append(
                ExtractedURL(
                    url=clean_url,
                    defanged_url=defang_url(clean_url),
                    scheme=parsed.scheme,
                    host=host,
                    domain=ext.domain,
                    subdomain=subdomain,
                    registered_domain=reg_domain,
                    tld=tld,
                    path=parsed.path or "/",
                    is_ip_host=is_ip,
                    is_shortener=is_short,
                    source=source,
                    source_locations=[source],
                )
            )

        # 1. Extract from HTML if present
        if body.has_html:
            try:
                soup = BeautifulSoup(body.text_html, "html.parser")
                for a in soup.find_all("a", href=True):
                    process_url(a["href"], "body_html")
                for img in soup.find_all("img", src=True):
                    process_url(img["src"], "body_html")
                for form in soup.find_all("form", action=True):
                    process_url(form["action"], "body_html")
            except Exception as e:
                logger.warning("URL parsing failed: %s", type(e).__name__)

        # 2. Extract from plain text
        if body.has_plain_text:
            matches = URL_REGEX.findall(body.text_plain)
            for m in matches:
                url_str = m[0] if isinstance(m, tuple) else m
                process_url(url_str, "body_text")

        return extracted

    def extract_all_ips(self, relay_chain: RelayChainSummary, metadata: EmailMetadata, body: BodyContent) -> List[ExtractedIP]:
        """Aggregate and classify all IP addresses extracted across relay chain, headers, and body."""
        seen_ips: Set[str] = set()
        extracted: List[ExtractedIP] = []

        def add_ip(ip_str: str, source: str) -> None:
            clean = ip_str.strip("[].,; ")
            if not clean or not is_valid_ip(clean):
                return
            if clean in seen_ips:
                for item in extracted:
                    if item.ip == clean and source not in item.source_locations:
                        item.source_locations.append(source)
                return
            seen_ips.add(clean)
            classification = classify_ip(clean)

            extracted.append(
                ExtractedIP(
                    ip=clean,
                    defanged_ip=defang_ip(clean),
                    version=classification.get("version", 4),
                    is_private=classification.get("is_private", False),
                    is_public=classification.get("is_public", True),
                    is_loopback=classification.get("is_loopback", False),
                    is_multicast=classification.get("is_multicast", False),
                    is_bogon=classification.get("is_bogon", False),
                    source=source,
                    source_locations=[source],
                )
            )

        # 1. From relay chain
        for hop in relay_chain.hops:
            if hop.from_ip:
                add_ip(hop.from_ip, "relay")

        # 2. From all headers
        for k, v in metadata.all_headers.items():
            if isinstance(v, list):
                for item in v:
                    for ip in extract_ips_from_text(str(item)):
                        add_ip(ip, "header")
            else:
                for ip in extract_ips_from_text(str(v)):
                    add_ip(ip, "header")

        # 3. From body
        for ip in extract_ips_from_text(body.text_plain):
            add_ip(ip, "body")

        return extracted

    def compute_threat_assessment(
        self,
        metadata: EmailMetadata,
        auth: AuthenticationSummary,
        relay_chain: RelayChainSummary,
        urls: List[ExtractedURL],
        attachments: List[AttachmentMetadata],
        body: BodyContent,
    ) -> InitialThreatAssessment:
        """Rule-based forensic threat risk assessment with full explainability."""
        indicators: List[ThreatIndicator] = []
        score = 0.0

        # 1. Authentication Checks
        if auth.spf_result == "fail":
            score += 25.0
            indicators.append(
                ThreatIndicator(
                    category="HEADER",
                    feature="SPF_FAIL",
                    description="UNVERIFIED supplied header reports SPF failure; no independent sending-IP authorization has been established.",
                    severity="HIGH",
                    observed_value=auth.spf_result,
                )
            )
        elif auth.spf_result == "softfail":
            score += 12.0
            indicators.append(
                ThreatIndicator(
                    category="HEADER",
                    feature="SPF_SOFTFAIL",
                    description="UNVERIFIED supplied header reports SPF softfail; this is an attacker-controlled claim.",
                    severity="MEDIUM",
                    observed_value=auth.spf_result,
                )
            )

        if auth.dkim_result == "fail":
            score += 25.0
            indicators.append(
                ThreatIndicator(
                    category="HEADER",
                    feature="DKIM_FAIL",
                    description="UNVERIFIED supplied header reports DKIM failure; no independent cryptographic verification is implied.",
                    severity="HIGH",
                    observed_value=auth.dkim_result,
                )
            )

        if auth.dmarc_result == "fail":
            score += 30.0
            indicators.append(
                ThreatIndicator(
                    category="HEADER",
                    feature="DMARC_FAIL",
                    description="UNVERIFIED supplied header reports DMARC failure; independent alignment and policy verification are unavailable here.",
                    severity="CRITICAL",
                    observed_value=auth.dmarc_result,
                )
            )

        # 2. Identity & Spoofing Checks
        from_domain = metadata.from_sender.domain
        return_domain = metadata.return_path.split("@")[-1].lower() if metadata.return_path and "@" in metadata.return_path else ""

        if from_domain and return_domain and from_domain != return_domain:
            score += 15.0
            indicators.append(
                ThreatIndicator(
                    category="IDENTITY",
                    feature="DOMAIN_MISMATCH_RETURN_PATH",
                    description=f"From address domain ({from_domain}) does not match Return-Path domain ({return_domain}).",
                    severity="MEDIUM",
                    observed_value={"from_domain": from_domain, "return_path_domain": return_domain},
                )
            )

        # Display name deception (e.g., display name is "CEO <ceo@corporate.com>" but address is "attacker@evil.com")
        display_name = metadata.from_sender.display_name
        if "@" in display_name:
            deceptive_email_in_name = parseaddr(display_name)[1].lower()
            if deceptive_email_in_name and deceptive_email_in_name != metadata.from_sender.address:
                score += 35.0
                indicators.append(
                    ThreatIndicator(
                        category="IDENTITY",
                        feature="DISPLAY_NAME_DECEPTION",
                        description=f"Display name embeds a deceptive email address ({deceptive_email_in_name}) conflicting with actual sender ({metadata.from_sender.address}).",
                        severity="CRITICAL",
                        observed_value={"display_name": display_name, "actual_sender": metadata.from_sender.address},
                    )
                )

        # 3. URL Observables
        ip_urls = [u for u in urls if u.is_ip_host]
        if ip_urls:
            score += 25.0
            indicators.append(
                ThreatIndicator(
                    category="URL",
                    feature="IP_BASED_URL",
                    description=f"Found {len(ip_urls)} URL(s) pointing directly to raw IP addresses rather than domain names.",
                    severity="HIGH",
                    observed_value=[u.defanged_url for u in ip_urls],
                )
            )

        shortened_urls = [u for u in urls if u.is_shortener]
        if shortened_urls:
            score += 10.0
            indicators.append(
                ThreatIndicator(
                    category="URL",
                    feature="URL_SHORTENER_DETECTED",
                    description=f"Detected {len(shortened_urls)} URL shortener link(s) hiding the actual destination.",
                    severity="LOW",
                    observed_value=[u.defanged_url for u in shortened_urls],
                )
            )

        # 4. Attachment Observables
        suspicious_attachments = [a for a in attachments if a.is_suspicious_extension]
        if suspicious_attachments:
            score += 35.0
            indicators.append(
                ThreatIndicator(
                    category="ATTACHMENT",
                    feature="SUSPICIOUS_ATTACHMENT_EXTENSION",
                    description=f"Found {len(suspicious_attachments)} executable or script attachment(s).",
                    severity="CRITICAL",
                    observed_value=[{"name": a.filename, "sha256": a.sha256} for a in suspicious_attachments],
                )
            )

        # 5. Content Urgency Check
        combined_text = (metadata.subject + " " + body.text_plain).lower()
        matched_keywords = [kw for kw in URGENCY_KEYWORDS if kw in combined_text]
        if matched_keywords:
            score += min(15.0, len(matched_keywords) * 5.0)
            indicators.append(
                ThreatIndicator(
                    category="CONTENT",
                    feature="URGENCY_KEYWORDS_DETECTED",
                    description=f"Email contains urgency / credential manipulation language: {', '.join(matched_keywords[:3])}",
                    severity="MEDIUM",
                    observed_value=matched_keywords,
                )
            )

        # Normalize score
        final_score = min(100.0, score)
        if final_score >= 70.0:
            classification = "PHISHING"
        elif final_score >= 40.0:
            if any(i.feature.startswith("SPF_") or i.feature.startswith("DKIM_") or "DECEPTION" in i.feature for i in indicators):
                classification = "SPOOFED"
            else:
                classification = "SUSPICIOUS"
        else:
            classification = "BENIGN"

        explanation = (
            f"LEGACY / PRELIMINARY UNVERIFIED assessment; submitted authentication claims are not independently verified. Risk score of {final_score:.1f}/100 calculated from {len(indicators)} observable forensic indicators. "
            f"Classification: {classification}."
        )

        return InitialThreatAssessment(
            risk_score=round(final_score, 1),
            classification=classification,
            confidence=0.90 if indicators else 0.95,
            indicators=indicators,
            explanation=explanation,
        )

    def parse(self) -> EmailAnalysisResponse:
        """Run the full forensic parsing pipeline and return structured analysis result."""
        case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        analyzed_at = datetime.now(timezone.utc).isoformat()

        metadata = self.extract_metadata()
        authentication = self.extract_authentication()
        relay_chain = self.extract_relay_chain()
        body, mime_structure, attachments = self.extract_body_and_structure()
        urls = self.extract_urls(body)
        ips = self.extract_all_ips(relay_chain, metadata, body)

        threat_assessment = self.compute_threat_assessment(
            metadata=metadata,
            auth=authentication,
            relay_chain=relay_chain,
            urls=urls,
            attachments=attachments,
            body=body,
        )

        return EmailAnalysisResponse(
            success=True,
            case_id=case_id,
            analyzed_at=analyzed_at,
            filename=self.filename,
            file_size_bytes=self.file_size,
            evidence_hashes=EvidenceHashes(**self.evidence_hashes),
            metadata=metadata,
            authentication=authentication,
            relay_chain=relay_chain,
            urls=urls,
            ips=ips,
            attachments=attachments,
            mime_structure=mime_structure,
            body=body,
            threat_assessment=threat_assessment,
        )
