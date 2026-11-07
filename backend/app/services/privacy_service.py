from __future__ import annotations
import copy
import re
import ipaddress
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
        from backend.app.schemas.analysis import EmailAnalysisResponse
        return EmailAnalysisResponse.model_validate(cls.redact_analysis(analysis.model_dump(mode="json")))

    @classmethod
    def redact_analysis(cls, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a redacted presentation view dictionary without modifying underlying stored evidence."""
        names = set()
        def find_names(value):
            if isinstance(value, dict):
                if isinstance(value.get("display_name"), str) and value["display_name"]: names.add(value["display_name"])
                for child in value.values(): find_names(child)
            elif isinstance(value,list):
                for child in value: find_names(child)
        find_names(analysis_data)
        def text(value):
            for name in sorted(names,key=len,reverse=True): value=value.replace(name,cls.mask_name(name))
            value=re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",lambda m:cls.mask_email(m[0]),value)
            value=re.sub(r"\b(\d{1,3})(?:\.|\[\.\])(\d{1,3})(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}\b",r"\1.\2.***.***",value)
            value=re.sub(r"(?<![a-zA-Z0-9:])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9]{0,4}(?![a-zA-Z0-9:])", lambda m: "[masked IPv6]" if ("::" in m[0] or m[0].count(":") >= 7) else m[0],value)
            return value
        def visit(value):
            if isinstance(value,str):return text(value)
            if isinstance(value,list):return [visit(item) for item in value]
            if isinstance(value,dict):return {text(key):visit(item) for key,item in value.items()}
            return value
        redacted=visit(analysis_data)
        redacted["privacy_redaction_applied"]=True
        return redacted
