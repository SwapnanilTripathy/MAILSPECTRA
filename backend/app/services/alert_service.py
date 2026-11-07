from __future__ import annotations
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.core.assessment import severity_for_score
from backend.app.core.logging import logger

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse


class SecurityAlert(BaseModel):
    alert_id: str
    case_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    title: str
    threat_classification: str
    risk_score: float
    created_at: str
    triggers: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    requires_immediate_action: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class AlertEvaluationResult(BaseModel):
    is_alert_generated: bool
    alert: Optional[SecurityAlert] = None
    evaluation_timestamp: str
    configured_high_threshold: float
    configured_critical_threshold: float


# In-memory recent alerts buffer for real-time dashboard notification feed
_RECENT_ALERTS: List[SecurityAlert] = []


class AlertService:
    """Evaluates risk score thresholds and observable evidence to dispatch structured security alerts."""

    @classmethod
    def evaluate_analysis(cls, analysis: EmailAnalysisResponse) -> AlertEvaluationResult:
        score = analysis.threat_assessment.risk_score
        classification = analysis.threat_assessment.classification
        now_iso = datetime.now(timezone.utc).isoformat()
        
        crit_thresh = settings.CRITICAL_ALERT_SCORE
        high_thresh = settings.ALERT_THRESHOLD_SCORE

        triggers: List[str] = []
        recommendations: List[str] = []

        severity = severity_for_score(score)
        requires_action = severity in {"HIGH", "CRITICAL"}

        # 2. Extract specific triggers from evidence
        if analysis.observed_evidence:
            for ind in analysis.observed_evidence:
                if ind.severity in ["CRITICAL", "HIGH"]:
                    triggers.append(f"[{ind.category}] {ind.evidence}")
        elif analysis.threat_assessment.indicators:
            for ind in analysis.threat_assessment.indicators:
                if ind.severity in ["CRITICAL", "HIGH"]:
                    triggers.append(f"[{ind.category}] {ind.description}")

        # Add auth triggers if failed
        auth = analysis.authentication
        if auth.dmarc_result == "fail":
            triggers.append("[AUTHENTICATION] Supplied header reports DMARC failure (unverified).")
        if auth.spf_result == "fail":
            triggers.append("[AUTHENTICATION] Supplied header reports SPF failure (unverified).")
        if auth.dkim_result == "fail":
            triggers.append("[AUTHENTICATION] Supplied header reports DKIM failure (unverified).")

        # Add content triggers
        if hasattr(analysis, "content_intelligence") and analysis.content_intelligence:
            ci = analysis.content_intelligence
            for sig in getattr(ci, "signals", []):
                if sig.severity in ["CRITICAL", "HIGH"]:
                    triggers.append(f"[CONTENT] {sig.label}: {sig.explanation}")

        # De-duplicate triggers
        triggers = list(dict.fromkeys(triggers))

        # 3. Assemble Remediation Recommendations
        if classification in ["PHISHING", "CREDENTIAL_HARVESTING"]:
            recommendations.append("Block sender domain and target URL payloads at email gateway / DNS resolver.")
            recommendations.append("Initiate password reset for recipients who may have interacted with the link.")
        elif classification in ["BUSINESS_EMAIL_COMPROMISE", "FRAUD"]:
            recommendations.append("Notify finance department to place a temporary verification freeze on requested wire/bank transfers.")
            recommendations.append("Verify payment instructions via authorized out-of-band communication channel.")
        elif classification == "SPOOFED":
            recommendations.append("Verify SPF/DKIM/DMARC policies on target domain to enforce 'p=reject'.")
        elif severity in ["CRITICAL", "HIGH"]:
            recommendations.append("Isolate recipient workstation and inspect network logs for secondary beaconing.")

        recommendations.append("Export forensic-ready PDF incident report for evidence preservation.")

        # 4. Construct Alert Object
        alert_id = f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        alert_title = f"{severity} Threat Detected: {classification} ({score}/100)"

        alert = SecurityAlert(
            alert_id=alert_id,
            case_id=analysis.case_id,
            severity=severity,
            title=alert_title,
            threat_classification=classification,
            risk_score=score,
            created_at=now_iso,
            triggers=triggers[:8],
            recommended_actions=recommendations,
            requires_immediate_action=requires_action,
            details={
                "filename": analysis.filename,
                "sender": analysis.metadata.from_sender.address,
                "subject": analysis.metadata.subject,
                "sha256": analysis.evidence_hashes.sha256,
            },
        )

        # Buffer recent high/critical alerts
        if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            _RECENT_ALERTS.insert(0, alert)
            if len(_RECENT_ALERTS) > 50:
                _RECENT_ALERTS.pop()

        logger.info(f"Generated {severity} alert {alert_id} for case {analysis.case_id} (Score: {score})")

        return AlertEvaluationResult(
            is_alert_generated=requires_action or severity in ["CRITICAL", "HIGH", "MEDIUM"],
            alert=alert,
            evaluation_timestamp=now_iso,
            configured_high_threshold=high_thresh,
            configured_critical_threshold=crit_thresh,
        )

    @classmethod
    def get_recent_alerts(cls, limit: int = 20) -> List[SecurityAlert]:
        return _RECENT_ALERTS[:limit]
