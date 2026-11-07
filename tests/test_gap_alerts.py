import pytest
from sqlalchemy import select
from backend.app.services.email_parser import EmailForensicParser
from backend.app.services.alert_service import AlertService
from backend.app.ml.schemas import RiskAssessmentResult
from backend.app.services.threat_pipeline import pipeline
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import AlertRecord

@pytest.mark.parametrize('score,severity,generated', [(0,'INFORMATIONAL',False),(20,'LOW',False),(40,'MEDIUM',True),(65,'HIGH',True),(85,'CRITICAL',True)])
def test_canonical_alert_policy(benign_eml_bytes,score,severity,generated):
    a=EmailForensicParser(raw_bytes=benign_eml_bytes,filename='benign.eml').parse()
    a.threat_assessment.risk_score=100
    a.risk_assessment=RiskAssessmentResult(risk_score=score,classification='SUSPICIOUS')
    result=AlertService.evaluate_analysis(a)
    assert result.is_alert_generated is generated
    if generated:
        assert result.alert.risk_score==score
        assert result.alert.severity==severity
        assert result.alert.threat_classification=='SUSPICIOUS'
    else: assert result.alert is None

@pytest.mark.asyncio
async def test_actual_pipeline_alert_persistence(benign_eml_bytes,phishing_eml_bytes):
    for raw in (benign_eml_bytes,phishing_eml_bytes):
        result=await pipeline.analyze_bytes_async(raw, 'alert-gap.eml')
        expected=AlertService.evaluate_analysis(result)
        assert bool(result.security_alert)==expected.is_alert_generated
        async with AsyncSessionLocal() as db:
            rows=(await db.scalars(select(AlertRecord).where(AlertRecord.case_id==result.case_id))).all()
            assert len(rows)==int(expected.is_alert_generated)
        again=await pipeline.analyze_bytes_async(raw,'duplicate.eml')
        assert again.case_id==result.case_id
