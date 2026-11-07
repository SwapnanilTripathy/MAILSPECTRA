import hashlib
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from backend.app.main import app
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import ArtifactRecord
from backend.app.core.config import settings

@pytest.mark.asyncio
async def test_original_bytes_idempotency_and_tamper_detection(auth_headers):
    raw = b'From: evidence@example.test\r\nSubject: original byte evidence\r\n\r\nPreserve CRLF bytes.\r\n'
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test', headers=auth_headers) as client:
        first = await client.post('/api/v1/analyze/email', files={'file': ('../../evidence.eml', raw, 'message/rfc822')})
        assert first.status_code == 200
        data = first.json()
        assert data['artifact']['sha256'] == hashlib.sha256(raw).hexdigest()
        assert data['artifact']['filename'] == 'evidence.eml'
        second = await client.post('/api/v1/analyze/email', files={'file': ('duplicate.eml', raw, 'message/rfc822')})
        assert second.json()['case_id'] == data['case_id']
        async with AsyncSessionLocal() as db:
            artifact = await db.scalar(select(ArtifactRecord).where(ArtifactRecord.case_id == data['case_id']))
            path = Path(settings.UPLOAD_DIR) / artifact.storage_name
        assert path.read_bytes() == raw
        assert path.stat().st_mode & 0o777 == 0o600
        assert (await client.get(f"/api/v1/cases/{data['case_id']}/evidence/verify")).json()['integrity_verified']
        path.write_bytes(b'tampered synthetic evidence')
        assert not (await client.get(f"/api/v1/cases/{data['case_id']}/evidence/verify")).json()['integrity_verified']
        path.write_bytes(raw)

@pytest.mark.asyncio
async def test_ingestion_validation_and_failure_cleanup(auth_headers, monkeypatch):
    from backend.app.services.threat_pipeline import pipeline
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test', headers=auth_headers) as client:
        assert (await client.post('/api/v1/analyze/email', files={'file': ('bad.msg', b'bad', 'application/octet-stream')})).status_code == 415
        assert (await client.post('/api/v1/analyze/raw', json={'raw_content':'not an email'})).status_code == 400
        monkeypatch.setattr(settings, 'MAX_UPLOAD_SIZE_MB', 1)
        assert (await client.post('/api/v1/analyze/raw', json={'raw_content':'x'*1048577})).status_code == 413
        root = Path(settings.UPLOAD_DIR)
        before = set(root.glob('*'))
        async def broken(*args, **kwargs): raise RuntimeError('private path must not leak')
        monkeypatch.setattr(pipeline, '_analyze', broken)
        response = await client.post('/api/v1/analyze/raw', json={'raw_content':'From: fail@example.test\nSubject: failure cleanup\n\nbody'})
        assert response.status_code == 500
        assert 'private path' not in response.text
        assert set(root.glob('*')) == before


def test_migration_preserves_legacy_records(tmp_path):
    from sqlalchemy import create_engine, text
    from migrations.baseline_schema import Base
    from alembic import command
    from alembic.config import Config
    engine = create_engine('sqlite:///' + str(tmp_path / 'legacy.db'))
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(Base.metadata.tables["cases"].insert().values(case_id="LEGACY", filename="legacy.eml", subject="Preserve me"))
        config = Config('alembic.ini'); config.attributes['connection'] = connection
        command.upgrade(config, 'head')
        assert connection.execute(text("SELECT subject FROM cases WHERE case_id='LEGACY'")).scalar() == 'Preserve me'
        assert connection.execute(text('SELECT version_num FROM alembic_version')).scalar() == '0002'
    engine.dispose()
