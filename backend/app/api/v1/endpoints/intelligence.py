import hashlib
import ipaddress
import re
from typing import Literal, Any
from urllib.parse import urlparse
from fastapi import APIRouter
from pydantic import BaseModel, Field, model_validator
from backend.app.core.config import settings
from backend.app.intelligence.reputation import ThreatReputationService
from backend.app.intelligence.cache import cached_lookup
from backend.app.intelligence.domain_intelligence import calculate_entropy

router = APIRouter()

class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1,max_length=2048)
    indicator_type: Literal['IP','DOMAIN','URL','HASH']

    @model_validator(mode='after')
    def validate_indicator(self):
        self.indicator = self.indicator.strip()
        if self.indicator_type == 'IP': self.indicator = str(ipaddress.ip_address(self.indicator))
        elif self.indicator_type == 'HASH':
            if not re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',self.indicator): raise ValueError('Expected MD5, SHA1 or SHA256 hex digest')
        elif self.indicator_type == 'DOMAIN':
            self.indicator = self.indicator.encode('idna').decode().lower().rstrip('.')
            if len(self.indicator)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}',self.indicator): raise ValueError('Invalid domain')
        else:
            parsed = urlparse(self.indicator)
            if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username: raise ValueError('Expected an HTTP(S) URL without credentials')
        return self

class LookupResponse(BaseModel):
    indicator: str
    indicator_type: str
    provider: str
    status: str
    verdict: str
    source: str
    last_checked: str
    cache_hit: bool = False
    limitations: list[str] = Field(default_factory=list)
    lexical_entropy: float
    external_lookup_enabled: bool

@router.post('/lookup', response_model=LookupResponse)
async def lookup(payload: LookupRequest):
    key = hashlib.sha256(f'{settings.INTELLIGENCE_MODE}:{payload.indicator_type}:{payload.indicator}'.encode()).hexdigest()
    async def operation():
        result = await ThreatReputationService().query_indicator(payload.indicator,payload.indicator_type)
        return result.model_dump()
    result = await cached_lookup(key,'reputation',operation)
    return {**result,'lexical_entropy':calculate_entropy(payload.indicator),'external_lookup_enabled':settings.INTELLIGENCE_MODE=='live'}
