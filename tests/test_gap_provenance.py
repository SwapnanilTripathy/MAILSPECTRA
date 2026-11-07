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
        assert o.verification_status=='OBSERVED_UNVERIFIED'
        assert o.source_location['character_offsets'] is None
    assert any(o.observation_type=='HEADER' and o.source_location['occurrence_index']==0 for o in a.observations)
    assert any(o.observation_type=='RELAY' for o in a.observations)
    attachment=next(o for o in a.observations if o.observation_type=='ATTACHMENT_SHA256')
    assert attachment.source_location['mime_part_index']==3
    assert attachment.source_location['filename']=='sample.bin'
    assert a.evidence_manifest['verification_status']=='PRESENT_UNVERIFIED'
    assert path.read_bytes()==raw
