import pytest
from backend.app.core.assessment import CAPS, severity_for_score
from backend.app.ml.risk_engine import ThreatRiskEngine
from backend.app.ml.predictor import ThreatPredictor
from backend.app.ml.feature_extractor import FeatureExtractor
from backend.app.services.email_parser import EmailForensicParser
from backend.app.services.alert_service import AlertService

@pytest.mark.parametrize('score,severity',[(0,'INFORMATIONAL'),(19.99,'INFORMATIONAL'),(20,'LOW'),(40,'MEDIUM'),(60,'HIGH'),(80,'CRITICAL'),(100,'CRITICAL')])
def test_severity_boundaries(score,severity):
    assert severity_for_score(score) == severity

def test_normalized_components_and_fallback(phishing_eml_bytes):
    analysis = EmailForensicParser(phishing_eml_bytes).parse()
    prediction,_ = ThreatPredictor(auto_load=False).predict(analysis)
    result = ThreatRiskEngine.evaluate(analysis,prediction,FeatureExtractor.extract_structured_features(analysis))
    assert sum(CAPS.values()) == 100
    assert prediction.probabilities == {} and prediction.confidence == 0
    assert result.evidence_breakdown['model_threat_probability'] == 0
    assert not any(
        indicator.indicator == "ML_HIGH_THREAT_PROBABILITY"
        for indicator in result.indicators
    )
    assert result.risk_score == pytest.approx(sum(result.evidence_breakdown.values()))
    assert all(0 <= value <= CAPS[key] for key,value in result.evidence_breakdown.items())
    analysis.threat_assessment.risk_score = result.risk_score
    evaluation = AlertService.evaluate_analysis(analysis)
    if result.severity in {"MEDIUM", "HIGH", "CRITICAL"}:
        assert evaluation.alert.severity == result.severity
    else:
        assert evaluation.alert is None and not evaluation.is_alert_generated
