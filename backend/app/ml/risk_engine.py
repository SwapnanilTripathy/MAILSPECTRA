from __future__ import annotations
from backend.app.core.assessment import CAPS, ASSESSMENT_VERSION, severity_for_score
from typing import TYPE_CHECKING, Dict, List, Tuple
from backend.app.ml.schemas import (
    IndicatorCategory,
    IndicatorSeverity,
    MLPredictionResult,
    RiskAssessmentResult,
    SecurityIndicator,
    ThreatClass,
)

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse



class ThreatRiskEngine:
    """Combines machine learning prediction probabilities with multi-layer forensic observables

    to compute a transparent, fully explainable 0-100 cybersecurity threat risk score.
    """

    @classmethod
    def evaluate(
        cls,
        analysis: EmailAnalysisResponse,
        prediction: MLPredictionResult,
        structured_features: Dict[str, float],
    ) -> RiskAssessmentResult:
        indicators: List[SecurityIndicator] = []
        breakdown: Dict[str, float] = {
            "model_threat_probability": 0.0,
            "authentication_evidence": 0.0,
            "identity_evidence": 0.0,
            "url_evidence": 0.0,
            "attachment_evidence": 0.0,
            "content_evidence": 0.0,
        }

        # 1. Model Evidence (Up to 40 points)
        # Probability of threat = 1.0 - prob(LEGITIMATE)
        legit_prob = prediction.probabilities.get(ThreatClass.LEGITIMATE.value, 0.0)
        threat_prob = max(0.0, min(1.0, 1.0 - legit_prob))
        model_points = threat_prob * 40.0 if prediction.is_model_available else 0.0
        breakdown["model_threat_probability"] = round(model_points, 1)

        if threat_prob >= 0.7:
            indicators.append(
                SecurityIndicator(
                    indicator="ML_HIGH_THREAT_PROBABILITY",
                    category=IndicatorCategory.BEHAVIOR.value,
                    severity=IndicatorSeverity.HIGH.value,
                    observed=True,
                    evidence=f"ML Classifier predicts threat '{prediction.predicted_class}' with {prediction.confidence * 100:.1f}% confidence.",
                    weight=model_points,
                )
            )

        # 2. Authentication & Protocol Evidence (Up to 30 points)
        auth = analysis.authentication
        auth_points = 0.0

        if auth.dmarc_result == "fail":
            auth_points += 15.0
            indicators.append(
                SecurityIndicator(
                    indicator="DMARC_ALIGNMENT_FAILURE",
                    category=IndicatorCategory.AUTHENTICATION.value,
                    severity=IndicatorSeverity.CRITICAL.value,
                    observed=True,
                    evidence="Supplied header reports DMARC failure; this claim is not independently verified.",
                    weight=15.0,
                )
            )

        if auth.spf_result == "fail":
            auth_points += 10.0
            indicators.append(
                SecurityIndicator(
                    indicator="SPF_VALIDATION_FAILURE",
                    category=IndicatorCategory.AUTHENTICATION.value,
                    severity=IndicatorSeverity.HIGH.value,
                    observed=True,
                    evidence=f"Supplied header reports SPF {auth.spf_result}; not independently verified.",
                    weight=10.0,
                )
            )
        elif auth.spf_result == "softfail":
            auth_points += 5.0
            indicators.append(
                SecurityIndicator(
                    indicator="SPF_SOFTFAIL",
                    category=IndicatorCategory.AUTHENTICATION.value,
                    severity=IndicatorSeverity.MEDIUM.value,
                    observed=True,
                    evidence="SPF softfail detected. Sending host is questionable under domain policy.",
                    weight=5.0,
                )
            )

        if auth.dkim_result == "fail":
            auth_points += 10.0
            indicators.append(
                SecurityIndicator(
                    indicator="DKIM_SIGNATURE_FAILURE",
                    category=IndicatorCategory.AUTHENTICATION.value,
                    severity=IndicatorSeverity.HIGH.value,
                    observed=True,
                    evidence="Supplied header reports DKIM failure; not independently verified.",
                    weight=10.0,
                )
            )

        breakdown["authentication_evidence"] = round(min(30.0, auth_points), 1)

        # 3. Identity & Spoofing Evidence (Up to 25 points)
        meta = analysis.metadata
        identity_points = 0.0

        if structured_features.get("identity_display_name_sender_mismatch", 0) > 0:
            identity_points += 15.0
            indicators.append(
                SecurityIndicator(
                    indicator="DISPLAY_NAME_SPOOFING",
                    category=IndicatorCategory.IDENTITY.value,
                    severity=IndicatorSeverity.CRITICAL.value,
                    observed=True,
                    evidence=f"Display name '{meta.from_sender.display_name}' embeds an email conflicting with actual envelope sender '{meta.from_sender.address}'.",
                    weight=15.0,
                )
            )

        if structured_features.get("identity_return_path_mismatch", 0) > 0:
            identity_points += 8.0
            indicators.append(
                SecurityIndicator(
                    indicator="RETURN_PATH_MISMATCH",
                    category=IndicatorCategory.IDENTITY.value,
                    severity=IndicatorSeverity.MEDIUM.value,
                    observed=True,
                    evidence=f"Sender domain ({meta.from_sender.domain}) diverges from Return-Path ({meta.return_path}).",
                    weight=8.0,
                )
            )

        if structured_features.get("identity_reply_to_mismatch", 0) > 0:
            reply_addr = meta.reply_to[0].address if meta.reply_to else "unknown"
            identity_points += 10.0
            indicators.append(
                SecurityIndicator(
                    indicator="REPLY_TO_DIVERSION",
                    category=IndicatorCategory.IDENTITY.value,
                    severity=IndicatorSeverity.HIGH.value,
                    observed=True,
                    evidence=f"Replies will be diverted to external address '{reply_addr}' rather than sender '{meta.from_sender.address}'.",
                    weight=10.0,
                )
            )

        breakdown["identity_evidence"] = round(min(25.0, identity_points), 1)

        # 4. URL Observables Evidence (Up to 25 points)
        url_points = 0.0
        ip_urls = [u for u in analysis.urls if u.is_ip_host]
        if ip_urls:
            url_points += 15.0
            indicators.append(
                SecurityIndicator(
                    indicator="IP_HOST_HYPERLINK",
                    category=IndicatorCategory.URL.value,
                    severity=IndicatorSeverity.CRITICAL.value,
                    observed=True,
                    evidence=f"Detected {len(ip_urls)} URL(s) pointing directly to raw IP hosts (e.g., {ip_urls[0].defanged_url}).",
                    weight=15.0,
                )
            )

        shorteners = [u for u in analysis.urls if u.is_shortener]
        if shorteners:
            url_points += 6.0
            indicators.append(
                SecurityIndicator(
                    indicator="URL_SHORTENER_OBFUSCATION",
                    category=IndicatorCategory.URL.value,
                    severity=IndicatorSeverity.LOW.value,
                    observed=True,
                    evidence=f"Detected {len(shorteners)} URL shortener link(s) hiding real destination.",
                    weight=6.0,
                )
            )

        mismatches = structured_features.get("url_sender_domain_mismatch", 0)
        if mismatches > 0 and len(analysis.urls) > 0:
            url_points += min(8.0, mismatches * 2.0)

        breakdown["url_evidence"] = round(min(25.0, url_points), 1)

        # 5. Attachment Evidence (Up to 30 points)
        att_points = 0.0
        exec_atts = [a for a in analysis.attachments if a.is_suspicious_extension]
        macro_atts = [a for a in analysis.attachments if a.extension.lower() in {".docm", ".xlsm", ".pptm"}]

        if exec_atts:
            att_points += 25.0
            indicators.append(
                SecurityIndicator(
                    indicator="SUSPICIOUS_EXECUTABLE_ATTACHMENT",
                    category=IndicatorCategory.ATTACHMENT.value,
                    severity=IndicatorSeverity.CRITICAL.value,
                    observed=True,
                    evidence=f"Attached file '{exec_atts[0].filename}' uses high-risk executable/script extension ({exec_atts[0].extension}).",
                    weight=25.0,
                )
            )
        elif macro_atts:
            att_points += 20.0
            indicators.append(
                SecurityIndicator(
                    indicator="MACRO_ENABLED_DOCUMENT_ATTACHMENT",
                    category=IndicatorCategory.ATTACHMENT.value,
                    severity=IndicatorSeverity.HIGH.value,
                    observed=True,
                    evidence=f"Attached file '{macro_atts[0].filename}' contains macro execution capability.",
                    weight=20.0,
                )
            )

        breakdown["attachment_evidence"] = round(min(30.0, att_points), 1)

        # 6. Content Evidence (Up to 20 points)
        content_points = 0.0

        if structured_features.get("content_credential_harvest_keyword_count", 0) > 0:
            content_points += 10.0
            indicators.append(
                SecurityIndicator(
                    indicator="CREDENTIAL_HARVESTING_LANGUAGE",
                    category=IndicatorCategory.CONTENT.value,
                    severity=IndicatorSeverity.HIGH.value,
                    observed=True,
                    evidence="Email text solicits login credentials, password verification, or authentication tokens.",
                    weight=10.0,
                )
            )

        if structured_features.get("content_payment_wire_keyword_count", 0) > 0:
            content_points += 10.0
            indicators.append(
                SecurityIndicator(
                    indicator="PAYMENT_DIVERSION_BEC_LANGUAGE",
                    category=IndicatorCategory.CONTENT.value,
                    severity=IndicatorSeverity.HIGH.value,
                    observed=True,
                    evidence="Email contains wire transfer, invoice modification, or banking diversion instructions.",
                    weight=10.0,
                )
            )

        if structured_features.get("content_urgency_keyword_count", 0) > 0:
            content_points += 5.0
            indicators.append(
                SecurityIndicator(
                    indicator="ARTIFICIAL_URGENCY_PRESSURE",
                    category=IndicatorCategory.CONTENT.value,
                    severity=IndicatorSeverity.MEDIUM.value,
                    observed=True,
                    evidence="Message exerts psychological urgency to induce rapid unverified action.",
                    weight=5.0,
                )
            )

        breakdown["content_evidence"] = round(min(20.0, content_points), 1)

        # Normalize each old rule bucket to its explicit allocation. Categories are capped;
        # correlated model/rule signals remain a documented limitation, not independent probabilities.
        old_caps = {"authentication_evidence":30, "identity_evidence":25, "url_evidence":25, "attachment_evidence":30, "content_evidence":20}
        for key, old_cap in old_caps.items():
            breakdown[key] = round(breakdown[key] * CAPS[key] / old_cap, 2)
        final_score = round(sum(breakdown.values()), 2)
        severity = severity_for_score(final_score)
        classification = prediction.predicted_class if prediction.is_model_available else "UNKNOWN"
        if final_score < 40 and prediction.is_model_available:
            classification = "LEGITIMATE"
        if final_score >= 40 and classification in {"LEGITIMATE", "UNKNOWN"}:
            classification = "SUSPICIOUS"
        categories = {"AUTHENTICATION":"authentication_evidence", "IDENTITY":"identity_evidence", "URL":"url_evidence", "ATTACHMENT":"attachment_evidence", "CONTENT":"content_evidence", "BEHAVIOR":"model_threat_probability"}
        for category, key in categories.items():
            members = [item for item in indicators if item.category == category]
            total = sum(item.weight for item in members)
            for item in members:
                item.weight = round(breakdown[key] * item.weight / total, 2) if total else 0

        return RiskAssessmentResult(
            risk_score=final_score,
            severity=severity,
            classification=classification,

            model_confidence=prediction.confidence,
            evidence_breakdown=breakdown,
            indicators=indicators,
            methodology=ASSESSMENT_VERSION + ": bounded ML 40 + authentication 15 + identity 15 + URL 15 + attachment 10 + content 5; not calibrated",
        )
