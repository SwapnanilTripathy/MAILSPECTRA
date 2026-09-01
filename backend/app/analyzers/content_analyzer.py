from __future__ import annotations
import re
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from backend.app.schemas.analysis import BodyContent
from backend.app.schemas.email import AttachmentMetadata, EmailMetadata, ExtractedURL


class ContentSignal(BaseModel):
    category: str  # URGENCY, CREDENTIALS, FINANCIAL_BEC, SUSPENSION, IMPERSONATION, CTA, SOCIAL_ENGINEERING, URL_PATTERNS, ATTACHMENTS
    signal_type: str
    label: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: float
    matches: List[str] = Field(default_factory=list)
    evidence_snippet: str = ""
    explanation: str = ""


class ContentIntelligenceResult(BaseModel):
    total_signals_detected: int = 0
    risk_score_contribution: float = 0.0
    highest_severity: str = "INFORMATIONAL"
    signals: List[ContentSignal] = Field(default_factory=list)
    detected_categories: List[str] = Field(default_factory=list)
    summary: str = ""


# Lexical dictionaries with explainable patterns
URGENCY_PATTERNS = [
    (r"\burgent\b", "Urgency keyword: 'urgent'"),
    (r"\bimmediate(ly)?\s+action\b", "Demand for immediate action"),
    (r"\bwithin\s+\d+\s+(hours?|mins?|minutes?|days?)\b", "Artificial deadline pressure"),
    (r"\bexpires?\s+(today|soon|within\s+\d+)\b", "Time-limited expiration threat"),
    (r"\bfinal\s+notice\b", "Coercive final notice warning"),
    (r"\bprompt\s+attention\b", "High-pressure prompt attention request"),
    (r"\basap\b", "Urgent request acronym 'ASAP'"),
    (r"\btime\s+sensitive\b", "Explicit time-sensitivity cue"),
    (r"\bdo\s+not\s+ignore\b", "Coercive command 'do not ignore'"),
    (r"\bact\s+now\b", "Direct pressure imperative 'act now'"),
]

CREDENTIAL_PATTERNS = [
    (r"\bverify(\s+your)?\s+(account|identity|credentials?|details?|password)\b", "Account/identity verification request"),
    (r"\breset\s+(your\s+)?(password|passcode|credentials?|pin)\b", "Password reset solicitation"),
    (r"\b(confirm|update|validate)\s+(your\s+)?(credentials?|password|security\s+code)\b", "Credential confirmation solicitation"),
    (r"\b(login|sign[\s-]in)\s+(to\s+)?(your\s+)?(account|portal|dashboard|security)\b", "Login prompt to unverified portal"),
    (r"\bre[\s-]authenticate\b", "Re-authentication prompt"),
    (r"\bpasscode\b|\b2fa\s+code\b|\botp\b|\bsecurity\s+pin\b", "Authentication token/OTP solicitation"),
    (r"\bunusual\s+login\s+detected\b", "Unusual login notification pretense"),
]

FINANCIAL_BEC_PATTERNS = [
    (r"\bwire\s+transfer\b", "Wire transfer transaction reference"),
    (r"\bbank\s+(transfer|account|details|routing)\b", "Banking routing/account instruction"),
    (r"\b(overdue\s+|new\s+|unpaid\s+)?invoice\s+(attached|settlement|payment|update)\b", "Invoice modification or settlement request"),
    (r"\bswift\s+code\b|\biban\b|\brouting\s+number\b", "Bank identifier codes (SWIFT/IBAN/Routing)"),
    (r"\bpayroll\s+(update|change|direct\s+deposit)\b", "Payroll/direct deposit redirection attempt"),
    (r"\bvendor\s+payment\b|\bremittance\s+advice\b", "Vendor payment redirection pretense"),
    (r"\boutstanding\s+balance\b|\bpayment\s+overdue\b", "Payment overdue pressure"),
    (r"\bfinancial\s+settlement\b", "Urgent financial settlement notice"),
]

SUSPENSION_PATTERNS = [
    (r"\baccount\s+(has\s+been\s+)?(suspended|locked|restricted|disabled|terminated)\b", "Account suspension/lockout alert"),
    (r"\bunauthorized\s+access(\s+detected)?\b", "Unauthorized access security alert"),
    (r"\bsecurity\s+(breach|alert|incident)\b", "Severe security incident notification"),
    (r"\bpermanently\s+(closed|disabled|deleted)\b", "Threat of permanent account deletion"),
    (r"\baccess\s+(denied|blocked|temporarily\s+restricted)\b", "Access blockage pressure"),
]

IMPERSONATION_PATTERNS = [
    (r"\b(ceo|chief\s+executive(\s+officer)?)\b", "Chief Executive Officer (CEO) executive cue"),
    (r"\b(cfo|chief\s+financial(\s+officer)?)\b", "Chief Financial Officer (CFO) executive cue"),
    (r"\bboard\s+of\s+directors\b", "Board of Directors authority pretense"),
    (r"\bstrictly\s+confidential\b|\bconfidential\s+request\b", "Confidentiality pressure / secret handling demand"),
    (r"\bhandle\s+this\s+personally\b", "Direct executive personal handling demand"),
    (r"\bare\s+you\s+at\s+your\s+desk\b|\bare\s+you\s+available\b", "Classic BEC pretexting check-in"),
    (r"\bi\s+am\s+in\s+a\s+meeting\b", "Executive meeting pretext preventing phone verification"),
]

CTA_PATTERNS = [
    (r"\bclick\s+here(\s+immediately|\s+to|\s+now)?\b", "Generic high-pressure 'Click here' link"),
    (r"\bopen\s+(attached\s+|the\s+)?(document|file|attachment|invoice|pdf)\b", "Instruction to open attached executable or payload"),
    (r"\bverify\s+now\b|\bconfirm\s+now\b|\bupdate\s+now\b", "Immediate imperative action button cue"),
    (r"\bdownload\s+(the\s+)?(attachment|statement|file|document)\b", "Download prompt for external payload"),
    (r"\baccess\s+your\s+account\s+(here|now)\b", "Hyperlink redirection to account interface"),
]


class ContentIntelligenceAnalyzer:
    """Deterministic, explainable NLP and lexical content analyzer for email communications."""

    @classmethod
    def analyze(
        cls,
        metadata: EmailMetadata,
        body: BodyContent,
        urls: List[ExtractedURL],
        attachments: List[AttachmentMetadata],
    ) -> ContentIntelligenceResult:
        signals: List[ContentSignal] = []

        subject = metadata.subject or ""
        plain = body.text_plain or ""
        
        # Safely extract text from HTML without tags or scripts
        html_clean = ""
        if body.text_html:
            try:
                soup = BeautifulSoup(body.text_html, "html.parser")
                # Remove scripts and styles
                for s in soup(["script", "style", "head"]):
                    s.decompose()
                html_clean = soup.get_text(separator=" ")
            except Exception:
                html_clean = re.sub(r"<[^>]+>", " ", body.text_html)

        combined_text = f"{subject}\n{plain}\n{html_clean}".strip()
        combined_lower = combined_text.lower()

        # 1. Urgency Pressure Analysis
        urgency_matches = []
        for pat, desc in URGENCY_PATTERNS:
            found = re.findall(pat, combined_lower, re.IGNORECASE)
            if found:
                urgency_matches.append(desc)
        if urgency_matches:
            signals.append(
                ContentSignal(
                    category="URGENCY",
                    signal_type="URGENCY_PRESSURE_LANGUAGE",
                    label="Artificial Urgency & Time Pressure",
                    severity="HIGH" if len(urgency_matches) >= 2 else "MEDIUM",
                    confidence=min(0.95, 0.70 + (len(urgency_matches) * 0.10)),
                    matches=urgency_matches,
                    evidence_snippet=cls._extract_snippet(combined_text, ["urgent", "immediately", "within", "expires", "notice"]),
                    explanation=f"Email exerts psychological pressure via {len(urgency_matches)} urgency indicators ({', '.join(urgency_matches[:2])}).",
                )
            )

        # 2. Credential Solicitation Analysis
        cred_matches = []
        for pat, desc in CREDENTIAL_PATTERNS:
            found = re.findall(pat, combined_lower, re.IGNORECASE)
            if found:
                cred_matches.append(desc)
        if cred_matches:
            signals.append(
                ContentSignal(
                    category="CREDENTIALS",
                    signal_type="CREDENTIAL_HARVESTING_CUES",
                    label="Credential & Authentication Harvesting Pretext",
                    severity="CRITICAL" if len(cred_matches) >= 2 else "HIGH",
                    confidence=min(0.95, 0.75 + (len(cred_matches) * 0.10)),
                    matches=cred_matches,
                    evidence_snippet=cls._extract_snippet(combined_text, ["verify", "password", "login", "credentials", "authenticate"]),
                    explanation=f"Text prompts the recipient to disclose or verify login credentials or security tokens ({', '.join(cred_matches[:2])}).",
                )
            )

        # 3. Financial / BEC Language Analysis
        bec_matches = []
        for pat, desc in FINANCIAL_BEC_PATTERNS:
            found = re.findall(pat, combined_lower, re.IGNORECASE)
            if found:
                bec_matches.append(desc)
        if bec_matches:
            signals.append(
                ContentSignal(
                    category="FINANCIAL_BEC",
                    signal_type="PAYMENT_WIRE_DIVERSION_LANGUAGE",
                    label="Financial / Wire Transfer / BEC Indicators",
                    severity="CRITICAL" if ("wire transfer" in combined_lower or "routing" in combined_lower) else "HIGH",
                    confidence=min(0.95, 0.75 + (len(bec_matches) * 0.10)),
                    matches=bec_matches,
                    evidence_snippet=cls._extract_snippet(combined_text, ["wire", "transfer", "invoice", "bank", "payment", "payroll"]),
                    explanation=f"Message contains financial diversion cues targeting accounts, payments, or wire transfers ({', '.join(bec_matches[:2])}).",
                )
            )

        # 4. Account Suspension Pretext Analysis
        susp_matches = []
        for pat, desc in SUSPENSION_PATTERNS:
            found = re.findall(pat, combined_lower, re.IGNORECASE)
            if found:
                susp_matches.append(desc)
        if susp_matches:
            signals.append(
                ContentSignal(
                    category="SUSPENSION",
                    signal_type="ACCOUNT_SUSPENSION_PRETEXT",
                    label="Account Suspension & Restriction Warning",
                    severity="HIGH",
                    confidence=min(0.95, 0.70 + (len(susp_matches) * 0.10)),
                    matches=susp_matches,
                    evidence_snippet=cls._extract_snippet(combined_text, ["suspended", "locked", "unauthorized", "disabled", "restricted"]),
                    explanation=f"Email manufactures fear of account suspension or security lockouts to coerce compliance ({', '.join(susp_matches[:2])}).",
                )
            )

        # 5. Executive / Authority Impersonation Analysis
        imp_matches = []
        for pat, desc in IMPERSONATION_PATTERNS:
            found = re.findall(pat, combined_lower, re.IGNORECASE)
            if found:
                imp_matches.append(desc)
        if imp_matches:
            signals.append(
                ContentSignal(
                    category="IMPERSONATION",
                    signal_type="EXECUTIVE_IMPERSONATION_PRETEXT",
                    label="Executive Pretexting & Authority Assertion",
                    severity="HIGH" if len(imp_matches) >= 2 else "MEDIUM",
                    confidence=min(0.95, 0.70 + (len(imp_matches) * 0.10)),
                    matches=imp_matches,
                    evidence_snippet=cls._extract_snippet(combined_text, ["ceo", "cfo", "confidential", "meeting", "desk", "personally"]),
                    explanation=f"Message mimics corporate hierarchy or demands secret out-of-band execution ({', '.join(imp_matches[:2])}).",
                )
            )

        # 6. Suspicious Call-to-Action (CTA) Analysis
        cta_matches = []
        for pat, desc in CTA_PATTERNS:
            found = re.findall(pat, combined_lower, re.IGNORECASE)
            if found:
                cta_matches.append(desc)
        if cta_matches:
            signals.append(
                ContentSignal(
                    category="CTA",
                    signal_type="SUSPICIOUS_CALL_TO_ACTION",
                    label="Manipulative Call-To-Action (CTA) Prompts",
                    severity="MEDIUM",
                    confidence=0.75,
                    matches=cta_matches,
                    evidence_snippet=cls._extract_snippet(combined_text, ["click here", "open", "verify now", "download", "access"]),
                    explanation=f"Email contains direct imperative click or open cues ({', '.join(cta_matches[:2])}).",
                )
            )

        # 7. Suspicious Link Patterns
        ip_links = [u for u in urls if u.is_ip_host]
        short_links = [u for u in urls if u.is_shortener]
        if ip_links:
            signals.append(
                ContentSignal(
                    category="URL_PATTERNS",
                    signal_type="RAW_IP_HYPERLINKS",
                    label="Raw IP Host Destination Links",
                    severity="CRITICAL",
                    confidence=0.95,
                    matches=[u.defanged_url for u in ip_links],
                    evidence_snippet=ip_links[0].defanged_url,
                    explanation=f"Found {len(ip_links)} direct IP-hosted hyperlinks bypassing domain reputation controls.",
                )
            )
        if short_links:
            signals.append(
                ContentSignal(
                    category="URL_PATTERNS",
                    signal_type="URL_SHORTENER_OBFUSCATION",
                    label="URL Shortener Obfuscation",
                    severity="LOW",
                    confidence=0.80,
                    matches=[u.defanged_url for u in short_links],
                    evidence_snippet=short_links[0].defanged_url,
                    explanation=f"Detected {len(short_links)} URL shortener links obscuring the final target hostname.",
                )
            )

        # 8. Attachment Indicators
        suspicious_atts = [a for a in attachments if a.is_suspicious_extension]
        if suspicious_atts:
            signals.append(
                ContentSignal(
                    category="ATTACHMENTS",
                    signal_type="SUSPICIOUS_EXECUTABLE_ATTACHMENT",
                    label="High-Risk Attachment Payload",
                    severity="CRITICAL",
                    confidence=0.98,
                    matches=[a.filename for a in suspicious_atts],
                    evidence_snippet=f"{suspicious_atts[0].filename} (SHA256: {suspicious_atts[0].sha256[:16]}...)",
                    explanation=f"Attached file '{suspicious_atts[0].filename}' uses high-risk executable or script extension ({suspicious_atts[0].extension}).",
                )
            )

        # Calculate severity & score contribution
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
        highest_sev = "INFORMATIONAL"
        total_score_contrib = 0.0
        categories_seen = set()

        for s in signals:
            categories_seen.add(s.category)
            if sev_order.get(s.severity, 0) > sev_order.get(highest_sev, 0):
                highest_sev = s.severity
            
            if s.severity == "CRITICAL":
                total_score_contrib += 25.0
            elif s.severity == "HIGH":
                total_score_contrib += 15.0
            elif s.severity == "MEDIUM":
                total_score_contrib += 8.0
            elif s.severity == "LOW":
                total_score_contrib += 3.0

        total_score_contrib = min(50.0, total_score_contrib)

        summary_text = (
            f"Analyzed email content and identified {len(signals)} structured threat signal(s) "
            f"across {len(categories_seen)} categories ({', '.join(sorted(categories_seen)) if categories_seen else 'None'}). "
            f"Highest severity: {highest_sev}."
        ) if signals else "Content analysis completed: No malicious or deceptive language patterns detected."

        return ContentIntelligenceResult(
            total_signals_detected=len(signals),
            risk_score_contribution=round(total_score_contrib, 1),
            highest_severity=highest_sev,
            signals=signals,
            detected_categories=sorted(list(categories_seen)),
            summary=summary_text,
        )

    @classmethod
    def _extract_snippet(cls, text: str, anchor_keywords: List[str], max_len: int = 140) -> str:
        """Extract short context snippet containing the matching keyword."""
        lines = text.splitlines()
        for line in lines:
            line_clean = " ".join(line.split())
            line_lower = line_clean.lower()
            for kw in anchor_keywords:
                if kw in line_lower:
                    if len(line_clean) <= max_len:
                        return line_clean
                    idx = line_lower.find(kw)
                    start = max(0, idx - 40)
                    end = min(len(line_clean), idx + 80)
                    snippet = line_clean[start:end].strip()
                    if start > 0:
                        snippet = "..." + snippet
                    if end < len(line_clean):
                        snippet = snippet + "..."
                    return snippet
        return ""
