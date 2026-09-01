from __future__ import annotations
import copy
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse


class PrivacyService:
    """Provides sensitive-field masking and PII redaction for presentation views while preserving evidence integrity."""

    @staticmethod
    def mask_email(email_str: Optional[str]) -> str:
        """Mask local part of an email address: user@example.com -> u***r@example.com."""
        if not email_str or "@" not in email_str:
            return email_str or ""
        try:
            local, domain = email_str.strip().split("@", 1)
            if len(local) <= 2:
                masked_local = local[0] + "*"
            else:
                masked_local = local[0] + ("*" * (len(local) - 2)) + local[-1]
            return f"{masked_local}@{domain}"
        except Exception:
            return email_str

    @staticmethod
    def mask_ip(ip_str: Optional[str]) -> str:
        """Mask host octets of an IP address: 198.51.100.25 -> 198.51.***.***."""
        if not ip_str:
            return ""
        clean = ip_str.strip("[] ")
        parts = clean.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***.***"
        # IPv6
        if ":" in clean:
            hextets = clean.split(":")
            if len(hextets) > 2:
                return f"{hextets[0]}:{hextets[1]}:****:****"
        return ip_str

    @staticmethod
    def mask_name(name_str: Optional[str]) -> str:
        """Mask personal display names: John Doe -> J***n D***e."""
        if not name_str:
            return ""
        words = name_str.strip().split()
        masked_words = []
        for w in words:
            if len(w) <= 2:
                masked_words.append(w[0] + "*" if w else "")
            else:
                masked_words.append(w[0] + ("*" * (len(w) - 2)) + w[-1])
        return " ".join(masked_words)

    @classmethod
    def apply_to_response(cls, analysis: EmailAnalysisResponse) -> EmailAnalysisResponse:
        """Apply PII masking directly onto EmailAnalysisResponse object for privacy-safe presentation."""
        # 1. Mask metadata addresses
        if analysis.metadata.from_sender.address:
            analysis.metadata.from_sender.address = cls.mask_email(analysis.metadata.from_sender.address)
        if analysis.metadata.from_sender.display_name:
            analysis.metadata.from_sender.display_name = cls.mask_name(analysis.metadata.from_sender.display_name)
        if analysis.metadata.from_sender.raw:
            analysis.metadata.from_sender.raw = cls.mask_email(analysis.metadata.from_sender.raw)

        for to_r in analysis.metadata.to_recipients:
            to_r.address = cls.mask_email(to_r.address)
            if to_r.display_name:
                to_r.display_name = cls.mask_name(to_r.display_name)

        for cc_r in analysis.metadata.cc_recipients:
            cc_r.address = cls.mask_email(cc_r.address)

        for reply_r in analysis.metadata.reply_to:
            reply_r.address = cls.mask_email(reply_r.address)

        if analysis.metadata.return_path:
            analysis.metadata.return_path = cls.mask_email(analysis.metadata.return_path)

        # 2. Mask relay chain IPs
        if analysis.relay_chain.origin_ip:
            analysis.relay_chain.origin_ip = cls.mask_ip(analysis.relay_chain.origin_ip)
            analysis.relay_chain.defanged_origin_ip = cls.mask_ip(analysis.relay_chain.defanged_origin_ip)

        for hop in analysis.relay_chain.hops:
            if hop.from_ip:
                hop.from_ip = cls.mask_ip(hop.from_ip)
                hop.defanged_from_ip = cls.mask_ip(hop.defanged_from_ip)

        # 3. Mask extracted IPs
        for ip_item in analysis.ips:
            ip_item.ip = cls.mask_ip(ip_item.ip)
            ip_item.defanged_ip = cls.mask_ip(ip_item.defanged_ip)

        return analysis

    @classmethod
    def redact_analysis(cls, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a redacted presentation view dictionary without modifying underlying stored evidence."""
        redacted = copy.deepcopy(analysis_data)

        # 1. Redact Metadata
        if "metadata" in redacted and isinstance(redacted["metadata"], dict):
            meta = redacted["metadata"]
            if "from_sender" in meta and isinstance(meta["from_sender"], dict):
                sender = meta["from_sender"]
                if sender.get("address"):
                    sender["address"] = cls.mask_email(sender["address"])
                if sender.get("display_name"):
                    sender["display_name"] = cls.mask_name(sender["display_name"])
                if sender.get("raw"):
                    sender["raw"] = cls.mask_email(sender["raw"])

            if "to_recipients" in meta and isinstance(meta["to_recipients"], list):
                for r in meta["to_recipients"]:
                    if isinstance(r, dict):
                        if r.get("address"):
                            r["address"] = cls.mask_email(r["address"])
                        if r.get("display_name"):
                            r["display_name"] = cls.mask_name(r["display_name"])

            if "reply_to" in meta and isinstance(meta["reply_to"], list):
                for r in meta["reply_to"]:
                    if isinstance(r, dict) and r.get("address"):
                        r["address"] = cls.mask_email(r["address"])

            if "return_path" in meta and meta["return_path"]:
                meta["return_path"] = cls.mask_email(meta["return_path"])

        # 2. Redact Relay Chain IP details
        if "relay_chain" in redacted and isinstance(redacted["relay_chain"], dict):
            rc = redacted["relay_chain"]
            if rc.get("origin_ip"):
                rc["origin_ip"] = cls.mask_ip(rc["origin_ip"])
            if rc.get("defanged_origin_ip"):
                rc["defanged_origin_ip"] = cls.mask_ip(rc["defanged_origin_ip"])
            if "hops" in rc and isinstance(rc["hops"], list):
                for hop in rc["hops"]:
                    if isinstance(hop, dict):
                        if hop.get("from_ip"):
                            hop["from_ip"] = cls.mask_ip(hop["from_ip"])
                        if hop.get("defanged_from_ip"):
                            hop["defanged_from_ip"] = cls.mask_ip(hop["defanged_from_ip"])

        # 3. Redact Extracted IPs
        if "ips" in redacted and isinstance(redacted["ips"], list):
            for ip_entry in redacted["ips"]:
                if isinstance(ip_entry, dict) and ip_entry.get("ip"):
                    ip_entry["ip"] = cls.mask_ip(ip_entry["ip"])
                    ip_entry["defanged_ip"] = cls.mask_ip(ip_entry.get("defanged_ip", ""))

        redacted["privacy_redaction_applied"] = True
        return redacted
