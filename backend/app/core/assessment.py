"""Versioned, uncalibrated decision-support policy shared by all consumers."""
from backend.app.core.config import settings
ASSESSMENT_VERSION = "mailspectra-risk-3.1"
CAPS = {"model_threat_probability":40.0, "authentication_evidence":15.0, "identity_evidence":15.0, "url_evidence":15.0, "attachment_evidence":10.0, "content_evidence":5.0}

def severity_for_score(score):
    if score >= settings.CRITICAL_ALERT_SCORE: return "CRITICAL"
    if score >= settings.ALERT_THRESHOLD_SCORE: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFORMATIONAL"
