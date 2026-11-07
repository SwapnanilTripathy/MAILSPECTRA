from email.message import EmailMessage
from backend.app.services.email_parser import EmailForensicParser
from backend.app.services.evidence_service import preserve, observations
from backend.app.core.versions import PARSER_VERSION


def test_source_references_and_honest_manifest(tmp_path,monkeypatch):
    from backend.app.core.config import settings
    monkeypatch.setattr(settings,'UPLOAD_DIR',str(tmp_path))
    msg=EmailMessage();msg['From']='a@example.test';msg['Subject']='Synthetic provenance';msg['Received']='from mail.example.test (8.8.8.8) by mx.example.test; Sat, 7 Nov 2026 10:00:00 +0000'
    msg.set_content('Visit https://example.test/path');msg.add_attachment(b'synthetic',maintype='application',subtype='octet-stream',filename='sample.bin')
    raw=msg.as_bytes();a=EmailForensicParser(raw_bytes=raw,filename='source.eml').parse();a.artifact,path=preserve(raw,'source.eml','test-account');observations(a)
    assert a.observations
    for o in a.observations:
        assert o.source_artifact_id==a.artifact.artifact_id
        assert o.parser_version==PARSER_VERSION
        assert o.verification_status==('UNAVAILABLE' if o.observation_type=='AUTHENTICATION_VERIFICATION' else 'OBSERVED_UNVERIFIED')
        assert o.source_location['character_offsets'] is None
    assert any(o.observation_type=='HEADER' and o.source_location['occurrence_index']==0 for o in a.observations)
    assert any(o.observation_type=='RELAY' for o in a.observations)
    attachment=next(o for o in a.observations if o.observation_type=='ATTACHMENT_SHA256')
    assert attachment.source_location['mime_part_index']==3
    assert attachment.source_location['filename']=='sample.bin'
    assert a.evidence_manifest['verification_status']=='PRESENT_UNVERIFIED'
    assert path.read_bytes()==raw


def test_crypto_status_is_scoped_to_verified_mechanism(tmp_path,monkeypatch,benign_eml_bytes):
    from backend.app.core.config import settings
    monkeypatch.setattr(settings,'UPLOAD_DIR',str(tmp_path))
    a=EmailForensicParser(raw_bytes=benign_eml_bytes,filename='source.eml').parse()
    a.artifact,_=preserve(benign_eml_bytes,'source.eml','test-account')
    a.authentication.verified={'dkim':{'result':'pass','method':'synthetic verification fixture'},'arc':{'result':'UNAVAILABLE'}}
    observations(a)
    verified=[o for o in a.observations if o.verification_status=='CRYPTOGRAPHICALLY_VERIFIED']
    assert len(verified)==1 and verified[0].source_location['mechanism']=='dkim'
    assert all(o.verification_status=='OBSERVED_UNVERIFIED' for o in a.observations if o.observation_type!='AUTHENTICATION_VERIFICATION')


import pytest
@pytest.mark.asyncio
async def test_pdf_tamper_is_separate_from_original(auth_headers):
    from httpx import AsyncClient,ASGITransport
    from backend.app.main import app
    from backend.app.database.session import AsyncSessionLocal
    from backend.app.models.entities import CaseRecord
    from pathlib import Path
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test',headers=auth_headers) as client:
        a=(await client.post('/api/v1/analyze/raw',json={'raw_content':'From: fixture@example.test\nSubject: Separate digest regression\n\nSynthetic message'})).json()
        cid=a['case_id']
        assert (await client.post(f'/api/v1/reports/generate/{cid}?mask_pii=true')).status_code==200
        async with AsyncSessionLocal() as db:
            path=Path((await db.get(CaseRecord,cid)).report_path)
        original=path.read_bytes()
        try:
            path.write_bytes(b'synthetic tamper')
            assert not (await client.get(f'/api/v1/reports/{cid}/verify')).json()['integrity_verified']
            assert (await client.get(f'/api/v1/cases/{cid}/evidence/verify')).json()['integrity_verified']
        finally: path.write_bytes(original)
