from __future__ import annotations
import re
from typing import TYPE_CHECKING, Any, Dict, List, Set, Tuple
import numpy as np

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse





SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "buzz",
    "bid", "icu", "cam", "fit", "rest", "surf", "monster", "cfd", "ru"
}

FREEMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "zoho.com", "yandex.com", "gmx.com"
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate action", "within 24 hours", "within 2 hours",
    "expires today", "final notice", "critical alert", "action required",
    "prompt attention", "asap", "time sensitive", "do not ignore"
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "verify account", "reset credentials", "sign in",
    "authenticate", "security code", "passcode", "account validation",
    "confirm identity", "update password", "re-authenticate", "login portal"
]

PAYMENT_WIRE_KEYWORDS = [
    "wire transfer", "bank transfer", "invoice", "overdue invoice", "routing number",
    "bank account", "remittance", "payment overdue", "swift code", "iban",
    "direct deposit", "payroll update", "financial settlement", "new bank details",
    "vendor payment", "outstanding balance"
]

ACCOUNT_SUSPENSION_KEYWORDS = [
    "account suspended", "temporarily restricted", "account locked", "unauthorized access",
    "access denied", "security breach", "suspended", "termination notice",
    "permanently disabled", "unusual activity detected", "account flagged"
]

IMPERSONATION_KEYWORDS = [
    "ceo", "chief executive", "cfo", "chief financial", "executive office",
    "board of directors", "confidential request", "strictly confidential",
    "handle this personally", "wire funds immediately", "executive assistant",
    "president", "managing director"
]

SUSPICIOUS_CTA_KEYWORDS = [
    "click here", "follow link", "verify now", "confirm now", "update immediately",
    "open document", "download attachment", "access account", "view invoice",
    "secure link", "validate now"
]

STRUCTURED_FEATURE_NAMES = [
    "auth_spf_pass",
    "auth_dkim_pass",
    "auth_dmarc_pass",
    "auth_all_pass",
    "auth_spf_fail",
    "auth_dkim_fail",
    "auth_dmarc_fail",
    "auth_results_missing",
    "identity_reply_to_mismatch",
    "identity_return_path_mismatch",
    "identity_display_name_email_embed",
    "identity_display_name_sender_mismatch",
    "identity_is_freemail_sender",
    "identity_suspicious_tld",
    "url_total_count",
    "url_unique_domains_count",
    "url_ip_host_count",
    "url_shortener_count",
    "url_suspicious_tld_count",
    "url_sender_domain_mismatch",
    "attachment_total_count",
    "attachment_suspicious_ext_count",
    "attachment_macro_count",
    "attachment_executable_count",
    "relay_total_hops",
    "relay_origin_is_private",
    "content_urgency_keyword_count",
    "content_credential_harvest_keyword_count",
    "content_payment_wire_keyword_count",
    "content_account_suspension_keyword_count",
    "content_impersonation_keyword_count",
    "content_suspicious_cta_keyword_count",
    "content_text_length",
    "content_html_to_text_ratio",
]


class FeatureExtractor:
    """Extracts structured forensic signals and text representations from parsed emails."""

    @staticmethod
    def get_structured_feature_names() -> List[str]:
        return list(STRUCTURED_FEATURE_NAMES)

    @classmethod
    def extract_text(cls, analysis: EmailAnalysisResponse) -> str:
        """Extract clean unified text string (Subject + Body Plain + Body HTML)."""
        subject = analysis.metadata.subject or ""
        plain = analysis.body.text_plain or ""
        html = analysis.body.text_html or ""
        
        # Simple tag removal for text representation
        clean_html = re.sub(r"<[^>]+>", " ", html)
        clean_html = " ".join(clean_html.split())

        combined = f"{subject}\n{plain}\n{clean_html}".strip()
        return combined

    @classmethod
    def extract_structured_features(cls, analysis: EmailAnalysisResponse) -> Dict[str, float]:
        """Extract dictionary of numeric engineered security signals."""
        features: Dict[str, float] = {name: 0.0 for name in STRUCTURED_FEATURE_NAMES}

        meta = analysis.metadata
        auth = analysis.authentication
        relays = analysis.relay_chain
        urls = analysis.urls
        attachments = analysis.attachments
        body = analysis.body

        # Only independently established results may affect model features.
        for mechanism in ('spf','dkim','dmarc'):
            result = auth.verified.get(mechanism, {}).get('result', 'UNKNOWN')
            if result in {'pass','fail'}:
                features[f'auth_{mechanism}_{result}'] = 1.0
        features['auth_all_pass'] = float(all(auth.verified.get(k,{}).get('result')=='pass' for k in ('spf','dkim','dmarc')))

        # 2. Identity signals
        from_domain = (meta.from_sender.domain or "").lower()
        sender_addr = (meta.from_sender.address or "").lower()
        display_name = meta.from_sender.display_name or ""

        # Reply-To mismatch
        if meta.reply_to:
            reply_domain = (meta.reply_to[0].domain or "").lower()
            if from_domain and reply_domain and from_domain != reply_domain:
                features["identity_reply_to_mismatch"] = 1.0

        # Return-Path mismatch
        if meta.return_path:
            return_domain = meta.return_path.split("@")[-1].lower() if "@" in meta.return_path else ""
            if from_domain and return_domain and from_domain != return_domain:
                features["identity_return_path_mismatch"] = 1.0

        # Display name email embedding & spoofing
        if "@" in display_name:
            features["identity_display_name_email_embed"] = 1.0
            embedded_match = re.search(r"[\w\.-]+@[\w\.-]+", display_name)
            if embedded_match:
                embedded_addr = embedded_match.group(0).lower()
                if embedded_addr != sender_addr:
                    features["identity_display_name_sender_mismatch"] = 1.0

        if from_domain in FREEMAIL_PROVIDERS:
            features["identity_is_freemail_sender"] = 1.0

        from_tld = from_domain.split(".")[-1] if "." in from_domain else ""
        if from_tld in SUSPICIOUS_TLDS:
            features["identity_suspicious_tld"] = 1.0

        # 3. URL signals
        features["url_total_count"] = float(len(urls))
        unique_domains = {u.registered_domain for u in urls if u.registered_domain}
        features["url_unique_domains_count"] = float(len(unique_domains))
        features["url_ip_host_count"] = float(sum(1 for u in urls if u.is_ip_host))
        features["url_shortener_count"] = float(sum(1 for u in urls if u.is_shortener))
        features["url_suspicious_tld_count"] = float(sum(1 for u in urls if u.tld in SUSPICIOUS_TLDS))
        
        mismatched_url_domains = 0
        for u in urls:
            if u.registered_domain and from_domain and u.registered_domain != from_domain:
                mismatched_url_domains += 1
        features["url_sender_domain_mismatch"] = float(mismatched_url_domains)

        # 4. Attachment signals
        features["attachment_total_count"] = float(len(attachments))
        features["attachment_suspicious_ext_count"] = float(sum(1 for a in attachments if a.is_suspicious_extension))
        macro_exts = {".docm", ".xlsm", ".pptm"}
        exec_exts = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".msi"}
        features["attachment_macro_count"] = float(sum(1 for a in attachments if a.extension.lower() in macro_exts))
        features["attachment_executable_count"] = float(sum(1 for a in attachments if a.extension.lower() in exec_exts))

        # 5. Relay signals
        features["relay_total_hops"] = float(relays.total_hops)
        if relays.hops and relays.hops[0].is_private_ip:
            features["relay_origin_is_private"] = 1.0

        # 6. Content lexical signals
        combined_text = (meta.subject + " " + body.text_plain + " " + body.text_html).lower()
        
        def count_keyword_matches(kw_list: List[str]) -> float:
            return float(sum(1 for kw in kw_list if kw in combined_text))

        features["content_urgency_keyword_count"] = count_keyword_matches(URGENCY_KEYWORDS)
        features["content_credential_harvest_keyword_count"] = count_keyword_matches(CREDENTIAL_KEYWORDS)
        features["content_payment_wire_keyword_count"] = count_keyword_matches(PAYMENT_WIRE_KEYWORDS)
        features["content_account_suspension_keyword_count"] = count_keyword_matches(ACCOUNT_SUSPENSION_KEYWORDS)
        features["content_impersonation_keyword_count"] = count_keyword_matches(IMPERSONATION_KEYWORDS)
        features["content_suspicious_cta_keyword_count"] = count_keyword_matches(SUSPICIOUS_CTA_KEYWORDS)
        
        features["content_text_length"] = min(len(combined_text) / 1000.0, 10.0)
        
        plain_len = max(1.0, float(body.text_plain_length))
        html_len = float(body.text_html_length)
        features["content_html_to_text_ratio"] = min(5.0, html_len / plain_len)

        return features

    @classmethod
    def get_feature_vector(cls, features_dict: Dict[str, float]) -> np.ndarray:
        """Convert structured dictionary to numpy array aligned with feature names."""
        return np.array([features_dict.get(name, 0.0) for name in STRUCTURED_FEATURE_NAMES], dtype=np.float64)
