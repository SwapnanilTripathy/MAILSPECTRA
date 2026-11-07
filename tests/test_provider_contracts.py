import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.intelligence.geoip import LiveIPInfoProvider
from backend.app.intelligence.reputation import LiveAbuseIPDBProvider, OfflineThreatIntelProvider

@pytest.mark.asyncio
async def test_live_provider_never_substitutes_fixture(monkeypatch):
    async def forbidden(*args,**kwargs): raise AssertionError('special-use address must not leave process')
    monkeypatch.setattr('backend.app.intelligence.http_client.provider_json',forbidden)
    geo = await LiveIPInfoProvider(token='synthetic').lookup('203.0.113.88')
    assert geo.status == 'SPECIAL_USE_IP' and geo.country is None
    rep = await LiveAbuseIPDBProvider(api_key='synthetic').query_indicator('203.0.113.88','IP')
    assert rep.status == 'SPECIAL_USE_IP' and rep.verdict == 'UNKNOWN'

@pytest.mark.asyncio
async def test_reputation_unknown_rate_limit_and_no_match(monkeypatch):
    unknown = await OfflineThreatIntelProvider().query_indicator('unknown.example.test','DOMAIN')
    assert unknown.verdict == 'UNKNOWN' and unknown.status == 'UNAVAILABLE'
    async def limited(*args,**kwargs): return 429,{}
    monkeypatch.setattr('backend.app.intelligence.http_client.provider_json', limited)
    provider = LiveAbuseIPDBProvider(api_key='synthetic')
    assert (await provider.query_indicator('8.8.8.8','IP')).status == 'RATE_LIMITED'
    async def no_match(*args,**kwargs): return 200,{'data':{'abuseConfidenceScore':0,'totalReports':0}}
    monkeypatch.setattr('backend.app.intelligence.http_client.provider_json',no_match)
    result = await provider.query_indicator('8.8.8.8','IP')
    assert result.verdict == 'NO_KNOWN_MATCH' and result.total_engines == 1

@pytest.mark.asyncio
async def test_intelligence_api_validation_and_cache(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test',headers=auth_headers) as client:
        invalid=await client.post('/api/v1/intelligence/lookup',json={'indicator':'not ip','indicator_type':'IP'})
        assert invalid.status_code==422
        payload={'indicator':'203.0.113.88','indicator_type':'IP'}
        first=(await client.post('/api/v1/intelligence/lookup',json=payload)).json()
        second=(await client.post('/api/v1/intelligence/lookup',json=payload)).json()
        assert first['status']=='FIXTURE' and first['source']=='OFFLINE_FIXTURE'
        assert second['cache_hit'] and second['last_checked']==first['last_checked']
        assert not second['external_lookup_enabled']
