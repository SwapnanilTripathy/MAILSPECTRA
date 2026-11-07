"""Bounded HTTP reads to an explicit provider host allowlist."""
import json
from urllib.parse import urlparse, urljoin
import httpx
from backend.app.core.config import settings

ALLOWED_HOSTS = {'ipinfo.io','api.abuseipdb.com','rdap.org','rdap.verisign.com','rdap.publicinterestregistry.org','rdap.nic.org','rdap.nic.xyz','rdap.namecheap.com'}

async def provider_json(url, headers=None):
    async with httpx.AsyncClient(timeout=settings.HTTP_INTEL_TIMEOUT_SECONDS, follow_redirects=False) as client:
        for _ in range(3):
            parsed = urlparse(url)
            if parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS or parsed.port not in {None,443} or parsed.username:
                return 502, {}
            async with client.stream('GET', url, headers=headers) as response:
                if response.status_code in {301,302,303,307,308}:
                    url = urljoin(url,response.headers.get('location',''))
                    headers = None  # Never forward provider credentials across a redirect.
                    continue
                if response.status_code != 200:
                    return response.status_code, {}
                chunks=[]; size=0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 1024*1024: raise ValueError('Provider response exceeds limit')
                    chunks.append(chunk)
                payload=json.loads(b''.join(chunks))
                if not isinstance(payload,dict): raise ValueError('Invalid provider payload')
                return 200,payload
        return 502,{}
