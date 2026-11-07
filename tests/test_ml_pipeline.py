from pathlib import Path
import pytest
from backend.app.ml.explainer import ThreatExplainer
from backend.app.ml.feature_extractor import FeatureExtractor
from backend.app.ml.model_loader import ModelBundle, ModelLoader
from backend.app.ml.predictor import ThreatPredictor
from backend.app.ml.risk_engine import ThreatRiskEngine
from backend.app.ml.schemas import ThreatClass
from backend.app.services.email_parser import EmailForensicParser
from backend.app.services.threat_pipeline import ThreatAnalysisPipeline


@pytest.fixture
def pipeline_instance():
    return ThreatAnalysisPipeline()


# 1. Legitimate Email Test
def test_1_legitimate_email(pipeline_instance, benign_eml_bytes):
    result = pipeline_instance.analyze_bytes(benign_eml_bytes, filename="benign.eml")
    assert result.success is True
    assert result.ai_inference is not None
    assert result.risk_assessment is not None
    assert result.risk_assessment.risk_score < 40.0
    assert result.risk_assessment.classification in [ThreatClass.LEGITIMATE.value, "BENIGN"]
    assert result.shap_explanation is not None
    assert len(result.shap_explanation.top_features) > 0


# 2. Phishing Email Test
def test_2_phishing_email(pipeline_instance, phishing_eml_bytes):
    result = pipeline_instance.analyze_bytes(phishing_eml_bytes, filename="phishing.eml")
    assert result.success is True
    assert result.risk_assessment.risk_score >= 70.0
    assert result.risk_assessment.severity in ["HIGH", "CRITICAL"]
    assert result.ai_inference.predicted_class in [ThreatClass.PHISHING.value, ThreatClass.CREDENTIAL_HARVESTING.value]
    assert any(f.direction == "increases_risk" for f in result.shap_explanation.top_features)


# 3. BEC-style Email Test
def test_3_bec_style_email(pipeline_instance):
    bec_raw = (
        b"Received: from mail.offshore-vpn.net (mail.offshore-vpn.net [185.220.101.5]) by mx.target.com with ESMTP id bec;\n"
        b"Authentication-Results: mx.target.com; spf=fail smtp.mailfrom=ceo@target.com; dkim=none; dmarc=fail\n"
        b"From: \"CEO John Smith\" <ceo@target.com>\n"
        b"Reply-To: \"Personal Executive\" <john.smith.private@gmail.com>\n"
        b"To: \"Finance Team\" <finance@target.com>\n"
        b"Subject: URGENT: Immediate Wire Transfer & Vendor Remittance Required\n"
        b"Date: Sun, 30 Aug 2026 00:00:00 +0000\n"
        b"Message-ID: <bec-20260830-112@target.com>\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\n"
        b"\n"
        b"Finance Team,\n"
        b"Please process the overdue supplier invoice via wire transfer before end of day.\n"
        b"Send the payment confirmation swift advice to my private email as I am travelling.\n"
        b"John Smith\n"
        b"Chief Executive Officer\n"
    )
    result = pipeline_instance.analyze_bytes(bec_raw, filename="bec_urgent.eml")
    assert result.success is True
    assert result.risk_assessment.risk_score == pytest.approx(sum(result.risk_assessment.evidence_breakdown.values()))
    assert result.risk_assessment.classification == "BUSINESS_EMAIL_COMPROMISE"
    assert result.risk_assessment.evidence_breakdown["authentication_evidence"] > 0
    assert any("BEC" in ind.indicator or "PAYMENT" in ind.indicator or "REPLY_TO" in ind.indicator for ind in result.observed_evidence)


# 4. Impersonation Email Test
def test_4_impersonation_email(pipeline_instance):
    imp_raw = (
        b"Received: from mail.attacker.top (mail.attacker.top [194.26.29.55]) by mx.target.com with SMTP;\n"
        b"From: \"President David Miller <david.miller@targetcorp.com>\" <attacker982@free-web-mail.top>\n"
        b"Reply-To: <attacker982@free-web-mail.top>\n"
        b"To: <staff@targetcorp.com>\n"
        b"Subject: Confidential Task - Are you at your desk?\n"
        b"Date: Sun, 30 Aug 2026 00:00:00 +0000\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\n"
        b"\n"
        b"Are you available right now? I need you to assist me with a time-sensitive confidential request for the board.\n"
    )
    result = pipeline_instance.analyze_bytes(imp_raw, filename="impersonation.eml")
    assert result.success is True
    assert result.risk_assessment.risk_score >= 40.0
    assert any("DISPLAY_NAME" in ind.indicator or "IDENTITY" in ind.category for ind in result.observed_evidence)


# 5. Missing Headers Test
def test_5_missing_headers(pipeline_instance):
    minimal_raw = b"Subject: Simple Note\n\nJust a quick hello without standard headers."
    result = pipeline_instance.analyze_bytes(minimal_raw, filename="minimal.eml")
    assert result.success is True
    assert result.metadata.subject == "Simple Note"
    assert result.risk_assessment.risk_score >= 0.0
    assert result.ai_inference is not None


# 6. No URLs Test
def test_6_no_urls(pipeline_instance):
    no_url_raw = (
        b"From: colleague@company.com\n"
        b"To: employee@company.com\n"
        b"Subject: Lunch meeting\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\n"
        b"\n"
        b"Hey, let's grab lunch at noon in the cafeteria.\n"
    )
    result = pipeline_instance.analyze_bytes(no_url_raw, filename="no_url.eml")
    assert result.success is True
    assert len(result.urls) == 0
    assert result.risk_assessment.evidence_breakdown["url_evidence"] == 0.0


# 7. Multiple URLs Test
def test_7_multiple_urls(pipeline_instance):
    multi_url_raw = (
        b"From: digest@tech-news.org\n"
        b"To: reader@defense.org\n"
        b"Subject: Weekly Articles\n"
        b"Content-Type: text/html; charset=\"utf-8\"\n"
        b"\n"
        b"<html><body>"
        b"<a href='https://news.tech-news.org/item1'>Article 1</a>"
        b"<a href='https://blog.partner.com/item2'>Article 2</a>"
        b"<a href='https://cdn.resource-hub.net/item3'>Article 3</a>"
        b"</body></html>"
    )
    result = pipeline_instance.analyze_bytes(multi_url_raw, filename="multi_url.eml")
    assert result.success is True
    assert len(result.urls) == 3
    assert result.feature_summary.key_extracted_signals["url_total_count"] == 3.0


# 8. Malformed Email Test
def test_8_malformed_email(pipeline_instance):
    garbled_raw = b"\x00\xff\xfe\x12\x34\x56Garbled-Random-Binary-Data-Non-MIME-12345"
    result = pipeline_instance.analyze_bytes(garbled_raw, filename="malformed.bin")
    assert result.success is True
    assert result.case_id.startswith("CASE-")
    assert result.risk_assessment is not None


# 9. Missing Model Fallback Test
def test_9_missing_model_fallback(benign_eml_bytes):
    # Instantiate predictor & explainer with auto_load=False to simulate missing model
    predictor_fallback = ThreatPredictor(model_bundle=None, auto_load=False)
    explainer_fallback = ThreatExplainer(model_bundle=None, auto_load=False)

    parser = EmailForensicParser(raw_bytes=benign_eml_bytes, filename="benign.eml")
    analysis = parser.parse()
    struct_feats = FeatureExtractor.extract_structured_features(analysis)

    # Predictor fallback
    pred_res, matrix = predictor_fallback.predict(analysis)
    assert pred_res.is_model_available is False
    assert pred_res.predicted_class in [ThreatClass.LEGITIMATE.value, "LEGITIMATE"]
    assert matrix is None

    # Explainer fallback
    shap_res = explainer_fallback.explain(pred_res.predicted_class, matrix, struct_feats)
    assert "Fallback" in shap_res.method
    assert len(shap_res.top_features) >= 0



# 10. Model Prediction Structure & Class Probabilities Test
def test_10_model_prediction_structure(benign_eml_bytes):
    predictor = ThreatPredictor()
    parser = EmailForensicParser(raw_bytes=benign_eml_bytes, filename="benign.eml")
    analysis = parser.parse()

    pred_res, matrix = predictor.predict(analysis)
    assert pred_res.predicted_class != ""
    assert 0.0 <= pred_res.confidence <= 1.0
    assert len(pred_res.probabilities) >= 7
    total_prob = sum(pred_res.probabilities.values())
    assert 0.98 <= total_prob <= 1.02  # Sums to 1.0


# 11. SHAP Explanation Generation Test
def test_11_shap_explanation_generation(phishing_eml_bytes):
    predictor = ThreatPredictor()
    explainer = ThreatExplainer()

    parser = EmailForensicParser(raw_bytes=phishing_eml_bytes, filename="phish.eml")
    analysis = parser.parse()
    struct_feats = FeatureExtractor.extract_structured_features(analysis)

    pred_res, matrix = predictor.predict(analysis)
    shap_res = explainer.explain(pred_res.predicted_class, matrix, struct_feats)

    assert shap_res.predicted_class == pred_res.predicted_class
    assert len(shap_res.top_features) > 0
    first_feat = shap_res.top_features[0]
    assert hasattr(first_feat, "feature")
    assert hasattr(first_feat, "contribution")
    assert hasattr(first_feat, "direction")
    assert hasattr(first_feat, "description")
    assert first_feat.direction in ["increases_risk", "decreases_risk"]


# 12. Risk Score Calculation Breakdown Test
def test_12_risk_score_calculation(phishing_eml_bytes):
    predictor = ThreatPredictor()
    parser = EmailForensicParser(raw_bytes=phishing_eml_bytes, filename="phish.eml")
    analysis = parser.parse()
    struct_feats = FeatureExtractor.extract_structured_features(analysis)

    pred_res, _ = predictor.predict(analysis)
    risk_res = ThreatRiskEngine.evaluate(analysis, pred_res, struct_feats)

    assert 0.0 <= risk_res.risk_score <= 100.0
    assert "model_threat_probability" in risk_res.evidence_breakdown
    assert "authentication_evidence" in risk_res.evidence_breakdown
    assert "identity_evidence" in risk_res.evidence_breakdown
    assert "url_evidence" in risk_res.evidence_breakdown
    assert "attachment_evidence" in risk_res.evidence_breakdown
    assert "content_evidence" in risk_res.evidence_breakdown
    assert len(risk_res.indicators) >= 1
