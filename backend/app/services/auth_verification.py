"""Independent verification adapters; uploaded headers never supply trusted SMTP context."""
import asyncio
import re
import dkim
import spf
import dns.resolver
import tldextract
from backend.app.core.config import settings
from backend.app.utils.network import classify_ip

_TLD = tldextract.TLDExtract(suffix_list_urls=())


def verify_spf(peer_ip, envelope_sender, helo):
    """Only call with independently acquired SMTP session metadata, not Received text."""
    if not classify_ip(peer_ip).get('is_public'):
        return {'result':'UNAVAILABLE', 'reason':'A public SMTP peer from trusted acquisition is required'}
    result, explanation = spf.check2(i=peer_ip, s=envelope_sender, h=helo, timeout=settings.DNS_TIMEOUT_SECONDS, querytime=settings.DNS_TIMEOUT_SECONDS)
    return {'result':result, 'domain':envelope_sender.rsplit('@',1)[-1] if envelope_sender else helo, 'method':'pyspf RFC7208', 'reason':explanation}


def verify_dkim(raw, dnsfunc=None):
    lookup = dnsfunc
    if lookup is None:
        def lookup(name, timeout=3):
            answer = dns.resolver.resolve(name.decode().rstrip('.'), 'TXT', lifetime=min(timeout, settings.DNS_TIMEOUT_SECONDS))
            records = [b''.join(rr.strings) for rr in answer]
            if len(records) != 1 or len(records[0]) > 16384:
                raise ValueError('Invalid DKIM key response')
            return records[0]
    verifier = dkim.DKIM(raw, timeout=settings.DNS_TIMEOUT_SECONDS, minkey=1024)
    signatures = [v for k,v in verifier.headers if k.lower() == b'dkim-signature']
    if not signatures:
        return {'result':'none','method':'dkimpy','domains':[]}
    passed = []
    try:
        for index, signature in enumerate(signatures[:5]):
            if verifier.verify(idx=index, dnsfunc=lookup):
                fields = dkim.util.parse_tag_value(signature)
                passed.append(fields[b'd'].decode('ascii').lower())
        return {'result':'pass' if passed else 'fail', 'domains':passed, 'method':'dkimpy', 'limitations':['At most five signatures checked; current DNS may differ from delivery-time DNS']}
    except dkim.ValidationError:
        return {"result":"fail","domains":passed,"method":"dkimpy","reason":"Signature validation failed"}
    except (dns.exception.DNSException, OSError):
        return {'result':'temperror','domains':passed,'method':'dkimpy','reason':'DNS unavailable'}
    except Exception:
        return {'result':'permerror','domains':passed,'method':'dkimpy','reason':'Malformed signature or key'}


def aligned(left, right, strict=False):
    left, right = left.lower().rstrip('.'), right.lower().rstrip('.')
    if strict: return left == right
    a, b = _TLD(left), _TLD(right)
    return (a.top_domain_under_public_suffix or left) == (b.top_domain_under_public_suffix or right)


def dmarc_alignment(from_domain, spf_result, dkim_result, policy):
    """Alignment against an explicitly retrieved DMARC policy, never reported results."""
    if not policy or not policy.startswith('v=DMARC1;'):
        return {'result':'UNAVAILABLE','reason':'DMARC policy unavailable'}
    tags = {}
    for pair in policy.split(';'):
        if '=' not in pair: continue
        key, value = pair.strip().split('=',1)
        if key in tags: return {'result':'permerror','reason':'Duplicate DMARC tag'}
        tags[key] = value
    if tags.get('p') not in {'none','quarantine','reject'}:
        return {'result':'permerror','reason':'Invalid DMARC policy'}
    spf_pass = spf_result.get('result') == 'pass' and aligned(spf_result.get('domain',''),from_domain,tags.get('aspf')=='s')
    dkim_pass = dkim_result.get('result') == 'pass' and any(aligned(d,from_domain,tags.get('adkim')=='s') for d in dkim_result.get('domains',[]))
    if spf_pass or dkim_pass: result = 'pass'
    elif spf_result.get('result') in {'UNAVAILABLE','temperror'} or dkim_result.get('result') in {'UNAVAILABLE','temperror'}: result = 'UNAVAILABLE'
    else: result = 'fail'
    return {'result':result,'policy':tags['p'],'spf_aligned':bool(spf_pass),'dkim_aligned':bool(dkim_pass),'method':'Independent result alignment'}


async def verify_authentication(raw, from_domain):
    unavailable = {'result':'UNAVAILABLE', 'reason':'External DNS verification is disabled'}
    result = {key:dict(unavailable) for key in ('spf','dkim','dmarc','arc')}
    result['spf']['reason'] = 'Saved email lacks independently acquired SMTP peer/envelope context'
    result['arc']['reason'] = 'ARC cryptographic validation is not implemented; header claims only'
    if not settings.VERIFY_AUTHENTICATION_DNS:
        return result
    result['dkim'] = await asyncio.to_thread(verify_dkim, raw)
    try:
        # Organizational-domain fallback follows the public suffix boundary.
        for domain in dict.fromkeys([from_domain, _TLD(from_domain).top_domain_under_public_suffix]):
            if not domain: continue
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, '_dmarc.' + domain, 'TXT', lifetime=settings.DNS_TIMEOUT_SECONDS)
                policies = [b''.join(rr.strings).decode() for rr in answers if b''.join(rr.strings).startswith(b'v=DMARC1')]
                if len(policies) == 1:
                    result['dmarc'] = dmarc_alignment(from_domain, result['spf'], result['dkim'], policies[0]); break
                if len(policies) > 1:
                    result['dmarc'] = {'result':'permerror','reason':'Multiple DMARC records'}; break
            except (dns.resolver.NXDOMAIN,dns.resolver.NoAnswer):
                continue
    except Exception:
        result['dmarc'] = {'result':'temperror','reason':'DNS lookup unavailable'}
    return result
