import pytest
from backend.app.intelligence.additional_providers import VirusTotalProvider, ShodanProvider

@pytest.mark.asyncio
@pytest.mark.parametrize('provider',[VirusTotalProvider,ShodanProvider])
async def test_no_credentials_or_special_ip_never_calls_network(provider,monkeypatch):
    async def forbidden(*a,**kw): pytest.fail('Unexpected network request')
    monkeypatch.setattr('backend.app.intelligence.additional_providers.provider_json',forbidden)
    assert (await provider('').query_indicator('8.8.8.8','IP')).status=='UNAVAILABLE'
    assert (await provider('synthetic').query_indicator('127.0.0.1','IP')).status.startswith('SPECIAL_USE')

@pytest.mark.asyncio
@pytest.mark.parametrize('code,status',[(401,'AUTH_ERROR'),(403,'AUTH_ERROR'),(404,'NOT_FOUND'),(429,'RATE_LIMITED'),(500,'ERROR')])
async def test_failure_states(code,status,monkeypatch):
    async def response(*a,**kw): return code,{}
    monkeypatch.setattr('backend.app.intelligence.additional_providers.provider_json',response)
    for provider in [VirusTotalProvider,ShodanProvider]:
        result=await provider('synthetic').query_indicator('8.8.8.8','IP')
        assert result.status==status and result.verdict=='UNKNOWN'

@pytest.mark.asyncio
async def test_existing_url_report_only(monkeypatch):
    async def response(url,headers,**kwargs):
        assert '/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLm9yZy9sb2dpbg' in url
        assert headers=={'x-apikey':'synthetic'} and kwargs['allow_redirects'] is False
        return 200,{'data':{'attributes':{'last_analysis_stats':{'malicious':2,'suspicious':1,'harmless':7},'last_analysis_date':123}}}
    monkeypatch.setattr('backend.app.intelligence.additional_providers.provider_json',response)
    r=await VirusTotalProvider('synthetic').query_indicator('https://example.org/login','URL')
    assert r.status=='AVAILABLE' and r.reputation_score==30 and r.total_engines==10
    assert r.context['provider_analysis_time']==123

@pytest.mark.asyncio
async def test_missing_statistics_and_zero_engines_unknown(monkeypatch):
    for stats in [{},{'malicious':0},{'malicious':-1}]:
        async def response(*a,**kw):return 200,{'data':{'attributes':{'last_analysis_stats':stats}}}
        monkeypatch.setattr('backend.app.intelligence.additional_providers.provider_json',response)
        r=await VirusTotalProvider('synthetic').query_indicator('example.org','DOMAIN')
        assert r.status!='AVAILABLE' and r.verdict=='UNKNOWN'

@pytest.mark.asyncio
async def test_shodan_ports_are_not_reputation(monkeypatch):
    async def response(url,**kwargs):
        assert 'minify=true' in url and kwargs['allow_redirects'] is False
        return 200,{'ip_str':'8.8.8.8','ports':[53,443],'org':'Synthetic organization'}
    monkeypatch.setattr('backend.app.intelligence.additional_providers.provider_json',response)
    r=await ShodanProvider('synthetic').query_indicator('8.8.8.8','IP')
    assert r.status=='AVAILABLE' and r.verdict=='UNKNOWN' and r.context['ports']==[53,443]
