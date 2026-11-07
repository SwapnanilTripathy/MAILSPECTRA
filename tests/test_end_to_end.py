import hashlib
import json
import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app

@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['benign','phishing'])
async def test_investigation_report_alert_workflow(auth_headers,kind):
    body = 'Hello team, our meeting starts tomorrow.' if kind=='benign' else 'Urgent: verify your password immediately at http://192.0.2.40/login'
    auth = 'spf=none; dkim=none; dmarc=none' if kind=='benign' else 'spf=fail; dkim=fail; dmarc=fail'
    raw=f'From: Synthetic Analyst <person@example.test>\r\nTo: recipient@example.test\r\nSubject: {kind} <b>escaped report</b>\r\nAuthentication-Results: untrusted.example.test; {auth}\r\n\r\n{body}\r\n'.encode()
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test',headers=auth_headers) as client:
        response=await client.post('/api/v1/analyze/email',files={'file':(kind+'.eml',raw,'message/rfc822')})
        assert response.status_code==200,response.text
        analysis=response.json();case_id=analysis['case_id']
        assert analysis['artifact']['sha256']==hashlib.sha256(raw).hexdigest()
        case=(await client.get(f'/api/v1/cases/{case_id}')).json()
        assert case['full_analysis']['risk_assessment']==analysis['risk_assessment']
        assert case['classification']==analysis['risk_assessment']['classification']
        assert (await client.get(f'/api/v1/cases/{case_id}/evidence/verify')).json()['integrity_verified']
        report=await client.post(f'/api/v1/reports/generate/{case_id}?mask_pii=true')
        assert report.status_code==200,report.text
        pdf=await client.get(f'/api/v1/reports/{case_id}/download')
        assert pdf.status_code==200 and pdf.content.startswith(b'%PDF')
        assert hashlib.sha256(pdf.content).hexdigest()==report.json()['sha256']
        assert (await client.get(f'/api/v1/reports/{case_id}/verify')).json()['integrity_verified']
        manifest=(await client.get(f'/api/v1/reports/{case_id}/manifest')).json()
        assert manifest['original_sha256']==hashlib.sha256(raw).hexdigest()
        assert manifest['privacy_redaction_applied']
        alerts=(await client.get('/api/v1/alerts?limit=100')).json()
        alert=next(item for item in alerts if item['case_id']==case_id)
        assert alert['risk_score']==analysis['risk_assessment']['risk_score']
        assert (await client.patch(f"/api/v1/alerts/{alert['alert_id']}",json={'status':'ACKNOWLEDGED'})).json()['status']=='ACKNOWLEDGED'
        assert next(a for a in (await client.get('/api/v1/alerts?limit=100')).json() if a['alert_id']==alert['alert_id'])['status']=='ACKNOWLEDGED'
        actions={item['action'] for item in (await client.get(f'/api/v1/cases/{case_id}/audit')).json()['items']}
        assert {'ARTIFACT_ANALYZED','REPORT_GENERATED','REPORT_VERIFIED','REPORT_DOWNLOADED','ALERT_UPDATED'} <= actions


def test_recursive_redaction_preserves_source():
    from backend.app.services.privacy_service import PrivacyService
    original={'metadata':{'from_sender':{'display_name':'Synthetic Person','address':'person@example.test'}}, 'nested':{'person@example.test':{'text':'Synthetic Person from person@example.test at 192.0.2.40 [2001:db8::1]'}}}
    redacted=PrivacyService.redact_analysis(original)
    assert 'person@example.test' not in json.dumps(redacted)
    assert '192.0.2.40' not in json.dumps(redacted)
    assert '2001:db8::1' not in json.dumps(redacted)
    assert 'person@example.test' in json.dumps(original)
