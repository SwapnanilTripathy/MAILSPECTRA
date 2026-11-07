"""Read-only provider reports. Never submits artifacts, scans hosts or fetches message URLs."""
import base64
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlparse
from backend.app.core.config import settings
from backend.app.intelligence.http_client import provider_json
from backend.app.intelligence.schemas import ThreatReputationInfo


def public_indicator(indicator, kind):
    target = urlparse(indicator).hostname if kind == 'URL' else indicator
    if kind == 'HASH':
        return bool(re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})', indicator))
    if not target: return False
    try: return ipaddress.ip_address(target).is_global
    except ValueError:
        return kind != 'IP' and '.' in target and not target.lower().rstrip('.').endswith(('.localhost','.local','.test','.invalid','.internal'))


def result(indicator, kind, provider, status='UNAVAILABLE', **kwargs):
    return ThreatReputationInfo(indicator=indicator, indicator_type=kind, provider=provider,
        status=status, verdict=kwargs.pop('verdict','UNKNOWN'),
        last_checked=datetime.now(timezone.utc).isoformat(), **kwargs)


def failure(code):
    return {401:'AUTH_ERROR',403:'AUTH_ERROR',404:'NOT_FOUND',429:'RATE_LIMITED'}.get(code,'ERROR')


class VirusTotalProvider:
    def __init__(self, api_key=None):
        self.api_key = settings.VIRUSTOTAL_API_KEY if api_key is None else api_key

    async def query_indicator(self, indicator, indicator_type):
        output = lambda status='UNAVAILABLE', **kw: result(indicator,indicator_type,'VirusTotal',status,**kw)
        if indicator_type not in {'IP','DOMAIN','URL','HASH'}: return output('UNSUPPORTED')
        if not public_indicator(indicator,indicator_type): return output('SPECIAL_USE_INDICATOR')
        if not self.api_key: return output(limitations=['Provider credential is not configured'])
        resource = {'IP':'ip_addresses','DOMAIN':'domains','URL':'urls','HASH':'files'}[indicator_type]
        identity = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip('=') if indicator_type=='URL' else indicator.lower()
        try:
            code, payload = await provider_json('https://www.virustotal.com/api/v3/'+resource+'/'+quote(identity,safe=''), {'x-apikey':self.api_key}, allow_redirects=False)
            if code != 200: return output(failure(code))
            data = payload['data']['attributes']; stats = data.get('last_analysis_stats',data.get('last_analysis_results'))
            if not isinstance(stats,dict) or 'malicious' not in stats: return output('ERROR',limitations=['Provider returned no analysis statistics'])
            if any(type(v) is not int or v<0 for v in stats.values()): return output('ERROR')
            total=sum(stats.values()); malicious=stats['malicious']; suspicious=stats.get('suspicious',0)
            if not total: return output('UNAVAILABLE',limitations=['No engines reported an assessment'])
            return output('AVAILABLE',verdict='MALICIOUS' if malicious else ('SUSPICIOUS' if suspicious else 'NO_KNOWN_MATCH'),
                malicious_votes=malicious,suspicious_votes=suspicious,total_engines=total,
                reputation_score=round(100*(malicious+suspicious)/total,2),
                context={'provider_analysis_time':data.get('last_analysis_date')},
                limitations=['Existing provider report; engine votes are correlated and are not a probability of harm'])
        except Exception:
            return output('ERROR',limitations=['Provider request or response validation failed'])


class ShodanProvider:
    def __init__(self, api_key=None):
        self.api_key = settings.SHODAN_API_KEY if api_key is None else api_key

    async def query_indicator(self, indicator, indicator_type):
        output = lambda status='UNAVAILABLE', **kw: result(indicator,indicator_type,'Shodan',status,**kw)
        if indicator_type != 'IP': return output('UNSUPPORTED')
        if not public_indicator(indicator,'IP'): return output('SPECIAL_USE_IP')
        if not self.api_key: return output(limitations=['Provider credential is not configured'])
        try:
            url='https://api.shodan.io/shodan/host/'+quote(indicator,safe='')+'?'+urlencode({'key':self.api_key,'minify':'true'})
            code,payload=await provider_json(url,allow_redirects=False)
            if code!=200: return output(failure(code))
            if payload.get('ip_str')!=indicator: return output('ERROR')
            ports=payload.get('ports',[])
            if not isinstance(ports,list) or any(type(p) is not int or not 0<=p<=65535 for p in ports): return output('ERROR')
            return output('AVAILABLE',context={'ports':sorted(set(ports)), 'organization':payload.get('org'), 'last_update':payload.get('last_update')},
                limitations=['Infrastructure observations only; open ports do not establish maliciousness'])
        except Exception:
            return output('ERROR',limitations=['Provider request or response validation failed'])
