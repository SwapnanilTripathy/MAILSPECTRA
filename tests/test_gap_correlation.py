from datetime import timedelta
from backend.app.graph.campaign_correlator import CampaignCorrelator, attachment_hashes, utc_timestamp
from backend.app.services.email_parser import EmailForensicParser
from backend.app.schemas.email import AttachmentMetadata
from backend.app.core.config import settings


def test_hash_and_temporal_context(benign_eml_bytes):
    a=EmailForensicParser(raw_bytes=benign_eml_bytes,filename='test.eml').parse()
    a.attachments=[AttachmentMetadata(filename='a',content_type='text/plain',size_bytes=1,md5='',sha1='',sha256='A'*64)]
    now=utc_timestamp(a.analyzed_at)
    hist={'case_id':'OTHER','attachment_hashes':['a'*64], 'created_at':(now-timedelta(days=settings.CORRELATION_WINDOW_DAYS)).isoformat()}
    matches,_,_=CampaignCorrelator.correlate_case(a,[hist])
    assert matches and matches[0].shared_values['attachment_hashes']==['a'*64]
    assert matches[0].temporal_context['elapsed_days']==settings.CORRELATION_WINDOW_DAYS
    hist['created_at']=(now-timedelta(days=settings.CORRELATION_WINDOW_DAYS,seconds=1)).isoformat()
    assert not CampaignCorrelator.correlate_case(a,[hist])[0]
    hist['created_at']=now.isoformat();hist['attachment_hashes']=['b'*64,'bad']
    assert not CampaignCorrelator.correlate_case(a,[hist])[0]
    assert attachment_hashes(['bad','A'*64])=={'a'*64}
    assert utc_timestamp('2026-01-01T02:00:00+02:00')==utc_timestamp('2026-01-01T00:00:00Z')


import pytest
@pytest.mark.asyncio
async def test_attachment_observables_idempotent():
    from email.message import EmailMessage
    from backend.app.services.threat_pipeline import pipeline
    from backend.app.database.session import AsyncSessionLocal
    from backend.app.models.entities import ObservableRecord
    from sqlalchemy import select
    import hashlib
    case_ids=[]
    digest=hashlib.sha256(b'synthetic shared attachment').hexdigest()
    for subject in ('Synthetic hash case one','Synthetic hash case two'):
        msg=EmailMessage();msg['From']='attachment@example.test';msg['Subject']=subject;msg.set_content('Synthetic body');msg.add_attachment(b'synthetic shared attachment',maintype='application',subtype='octet-stream',filename='shared.bin')
        raw=msg.as_bytes()
        result=await pipeline.analyze_bytes_async(raw,'synthetic.eml')
        assert (await pipeline.analyze_bytes_async(raw,'duplicate.eml')).case_id==result.case_id
        case_ids.append(result.case_id)
        async with AsyncSessionLocal() as db:
            rows=(await db.scalars(select(ObservableRecord).where(ObservableRecord.case_id==result.case_id,ObservableRecord.observable_type=='ATTACHMENT_SHA256'))).all()
            assert len(rows)==1 and rows[0].value==digest
    match=next(m for m in result.campaign_correlations if m.related_case_id==case_ids[0])
    assert match.shared_values['attachment_hashes']==[digest]
