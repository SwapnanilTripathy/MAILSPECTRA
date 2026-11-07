import secrets
from datetime import datetime, timedelta, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import delete
from backend.app.main import app
from backend.app.core.config import settings, Settings
from backend.app.core.security import hash_password, verify_password
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import UserRecord, LoginAttemptRecord

@pytest.mark.asyncio
async def test_all_private_routes_reject_anonymous():
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        for route in ['/cases', '/campaigns', '/reports', '/alerts', '/system/settings', '/dashboard/stats', '/auth/me', '/reports/no-case/download']:
            assert (await client.get('/api/v1' + route)).status_code == 401
        assert (await client.post('/api/v1/analyze/raw', json={'raw_content': 'test'})).status_code == 401

@pytest.mark.asyncio
async def test_invalid_expired_and_revoked_sessions(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        claims = jwt.get_unverified_claims(auth_headers['Authorization'].split()[1])
        claims['exp'] = datetime.now(timezone.utc) - timedelta(seconds=1)
        expired = jwt.encode(claims, settings.SECRET_KEY, algorithm='HS256')
        for token in ['demo-token', expired, jwt.encode(claims, 'wrong-secret', algorithm='HS256')]:
            assert (await client.get('/api/v1/auth/me', headers={'Authorization': 'Bearer ' + token})).status_code == 401
        assert (await client.get('/api/v1/auth/me', headers=auth_headers)).status_code == 200
        assert (await client.post('/api/v1/auth/logout', headers=auth_headers)).status_code == 200
        assert (await client.get('/api/v1/auth/me', headers=auth_headers)).status_code == 401

@pytest.mark.asyncio
async def test_roles_and_login_rate_limit(auth_headers):
    async with AsyncSessionLocal() as db:
        await db.execute(delete(LoginAttemptRecord))
        users = {role: role + '-' + secrets.token_hex(4) for role in ['viewer', 'analyst']}
        for role, name in users.items():
            db.add(UserRecord(username=name, role=role, hashed_password=hash_password('synthetic-long-password')))
        await db.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        for role, name in users.items():
            res = await client.post('/api/v1/auth/login', json={'username': name, 'password': 'synthetic-long-password'})
            headers = {'Authorization': 'Bearer ' + res.json()['access_token']}
            assert (await client.get('/api/v1/cases', headers=headers)).status_code == 200
            assert (await client.get('/api/v1/system/settings', headers=headers)).status_code == 403
            if role == 'viewer':
                assert (await client.post('/api/v1/analyze/raw', json={'raw_content': 'test'}, headers=headers)).status_code == 403
        for _ in range(settings.LOGIN_ATTEMPT_LIMIT - 2):
            assert (await client.post('/api/v1/auth/login', json={'username': 'nonexistent', 'password': 'password'})).status_code == 401
        assert (await client.post('/api/v1/auth/login', json={'username': 'nonexistent', 'password': 'password'})).status_code == 429


def test_password_hash_and_production_configuration():
    encoded = hash_password('synthetic-long-password')
    assert verify_password('synthetic-long-password', encoded)
    assert not verify_password('incorrect', encoded)
    assert not verify_password('incorrect', 'malformed')
    with pytest.raises(ValueError):
        Settings(_env_file=None, APP_ENV='production', SECRET_KEY='')
    with pytest.raises(ValueError):
        Settings(_env_file=None, APP_ENV='production', SECRET_KEY='x'*40)
