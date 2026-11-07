import pytest
from datetime import datetime,timedelta,timezone
from sqlalchemy import select
from httpx import AsyncClient,ASGITransport
from backend.app.main import app
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import RefreshTokenRecord,SessionRecord
from backend.app.services.email_parser import EmailForensicParser
from backend.app.ml.feature_extractor import FeatureExtractor
from backend.app.ml.predictor import ThreatPredictor
from backend.app.ml.risk_engine import ThreatRiskEngine
from backend.app.core.config import Settings


def test_reported_auth_does_not_change_features_or_score():
    results=[]
    for claim in ('','Authentication-Results: attacker.test; spf=pass; dkim=pass; dmarc=pass\n','Authentication-Results: attacker.test; spf=fail; dkim=fail; dmarc=fail\n'):
        a=EmailForensicParser(raw_bytes=('From: a@example.test\nSubject: Synthetic\n'+claim+'\nMeeting tomorrow').encode()).parse()
        features=FeatureExtractor.extract_structured_features(a)
        prediction,_=ThreatPredictor().predict(a)
        score=ThreatRiskEngine.evaluate(a,prediction,features)
        results.append((features,score.risk_score))
        assert all(v['result']=='UNAVAILABLE' for v in a.verified_authentication.values())
        assert a.reported_authentication['status']=='UNVERIFIED'
    assert results[0]==results[1]
    assert results[0][0]==results[2][0]
    assert 0 <= results[2][1]-results[0][1] <= 15
    a.authentication.verified['dkim']={'result':'fail','method':'test independent verification'}
    assert ThreatRiskEngine.evaluate(a,prediction,FeatureExtractor.extract_structured_features(a)).evidence_breakdown['authentication_evidence']>0


def test_production_database_explicit():
    options=dict(_env_file=None,APP_ENV='production',SECRET_KEY='abcdefghijklmnopqrstuvwxyz1234567890ABC',CORS_ORIGINS=['https://example.test'])
    with pytest.raises(ValueError,match='DATABASE_URL'): Settings(**options,DATABASE_URL='')
    with pytest.raises(ValueError,match='SQLite'): Settings(**options,DATABASE_URL='sqlite+aiosqlite:///x.db')
    assert Settings(**options,DATABASE_URL='postgres://u:p@localhost/db').DATABASE_URL.startswith('postgresql+asyncpg://')
    assert Settings(_env_file=None,APP_ENV='development',DATABASE_URL='sqlite+aiosqlite:///x.db').DATABASE_URL.startswith('sqlite')
    assert Settings(**options,DATABASE_URL='sqlite+aiosqlite:///x.db',ALLOW_SQLITE_PRODUCTION=True)

@pytest.mark.asyncio
async def test_refresh_rotation_reuse_logout_expiry(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as c:
        async def login():
            r=await c.post('/api/v1/auth/login',json={'username':'test-admin','password':'test-only-long-password'})
            assert r.status_code==200
            assert 'HttpOnly' in r.headers['set-cookie'] and 'SameSite=strict' in r.headers['set-cookie']
            return r.json()['access_token']
        await login();old=c.cookies.get('mailspectra_refresh')
        assert (await c.post('/api/v1/auth/refresh')).status_code==403
        headers={'X-Mailspectra-CSRF':'1'}
        assert (await c.post('/api/v1/auth/refresh',headers={**headers,'Origin':'https://evil.test'})).status_code==403
        r=await c.post('/api/v1/auth/refresh',headers=headers);assert r.status_code==200
        token=r.json()['access_token'];rotated=c.cookies.get('mailspectra_refresh');assert rotated!=old
        assert (await c.get('/api/v1/auth/me',headers={'Authorization':'Bearer '+token})).status_code==200
        assert (await c.post('/api/v1/auth/refresh',headers={**headers,'Cookie':'mailspectra_refresh='+old})).status_code==401
        assert (await c.get('/api/v1/auth/me',headers={'Authorization':'Bearer '+token})).status_code==401
        assert (await c.post('/api/v1/auth/refresh',headers=headers)).status_code==401
        token=await login()
        assert (await c.post('/api/v1/auth/logout',headers={'Authorization':'Bearer '+token})).status_code==200
        assert (await c.post('/api/v1/auth/refresh',headers=headers)).status_code==401
        await login()
        import hashlib
        digest=hashlib.sha256(c.cookies.get('mailspectra_refresh').encode()).hexdigest()
        async with AsyncSessionLocal() as db:
            refresh=await db.get(RefreshTokenRecord,digest)
            assert refresh and refresh.token_hash!=c.cookies.get('mailspectra_refresh')
            session=await db.get(SessionRecord,refresh.session_id)
            session.expires_at=datetime.now(timezone.utc)-timedelta(seconds=1)
            await db.commit()
        assert (await c.post('/api/v1/auth/refresh',headers=headers)).status_code==401

@pytest.mark.asyncio
@pytest.mark.parametrize('role',['viewer','analyst','admin'])
async def test_refresh_preserves_roles(auth_headers,role):
    from backend.app.models.entities import UserRecord,LoginAttemptRecord
    from backend.app.core.security import hash_password
    from sqlalchemy import delete
    import secrets
    name='refresh-'+secrets.token_hex(6)
    async with AsyncSessionLocal() as db:
        await db.execute(delete(LoginAttemptRecord))
        db.add(UserRecord(username=name,role=role,hashed_password=hash_password('synthetic-long-password')))
        await db.commit()
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as c:
        assert (await c.post('/api/v1/auth/login',json={'username':name,'password':'synthetic-long-password'})).status_code==200
        r=await c.post('/api/v1/auth/refresh',headers={'X-Mailspectra-CSRF':'1'});assert r.status_code==200
        h={'Authorization':'Bearer '+r.json()['access_token']}
        assert (await c.get('/api/v1/auth/me',headers=h)).json()['role']==role
        assert (await c.get('/api/v1/system/settings',headers=h)).status_code==(200 if role=='admin' else 403)
        if role=='viewer':assert (await c.post('/api/v1/analyze/raw',json={'raw_content':'x'},headers=h)).status_code==403


def test_production_missing_database_and_tls_query(monkeypatch):
    monkeypatch.delenv('DATABASE_URL',raising=False)
    opts=dict(_env_file=None,APP_ENV='production',SECRET_KEY='abcdefghijklmnopqrstuvwxyz1234567890ABC')
    with pytest.raises(ValueError,match='explicit DATABASE_URL'):Settings(**opts)
    normalized=Settings(**opts,DATABASE_URL='postgresql://u:p@localhost/db?sslmode=require')
    assert 'ssl=require' in normalized.DATABASE_URL and 'sslmode' not in normalized.DATABASE_URL

@pytest.mark.asyncio
async def test_concurrent_refresh_reuse_revokes_family(auth_headers):
    import asyncio
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as c:
        await c.post('/api/v1/auth/login',json={'username':'test-admin','password':'test-only-long-password'})
        cookie=c.cookies.get('mailspectra_refresh')
        h={'X-Mailspectra-CSRF':'1','Cookie':'mailspectra_refresh='+cookie}
        results=await asyncio.gather(c.post('/api/v1/auth/refresh',headers=h),c.post('/api/v1/auth/refresh',headers=h))
        assert sorted(r.status_code for r in results)==[200,401]
        token=next(r.json()['access_token'] for r in results if r.status_code==200)
        assert (await c.get('/api/v1/auth/me',headers={'Authorization':'Bearer '+token})).status_code==401
        assert (await c.post('/api/v1/auth/refresh',headers={**h,'Cookie':'mailspectra_refresh=invalid'})).status_code==401

@pytest.mark.asyncio
async def test_production_refresh_cookie_flags(monkeypatch):
    from fastapi import Response
    from types import SimpleNamespace
    from backend.app.core.config import settings
    from backend.app.api.v1.endpoints.auth import issue_refresh
    monkeypatch.setattr(settings,'APP_ENV','production')
    r=Response();saved=[]
    await issue_refresh(r,SimpleNamespace(add=saved.append),'synthetic-session',datetime.now(timezone.utc)+timedelta(days=7))
    header=r.headers['set-cookie']
    assert 'Secure' in header and 'HttpOnly' in header and 'SameSite=strict' in header
    assert 'Path=/api/v1/auth' in header and saved[0].token_hash not in header


def test_configuration_errors_do_not_print_credentials(monkeypatch):
    monkeypatch.delenv('DATABASE_URL',raising=False)
    secret='synthetic-sensitive-abcdefghijklmnopqrstuvwxyz-123456'
    with pytest.raises(ValueError) as error:
        Settings(_env_file=None,APP_ENV='production',SECRET_KEY=secret)
    assert secret not in str(error.value)
