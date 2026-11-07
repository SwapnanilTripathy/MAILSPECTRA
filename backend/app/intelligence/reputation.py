from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional
import httpx

from backend.app.core.config import settings
from backend.app.utils.network import classify_ip
from backend.app.core.logging import logger
from backend.app.intelligence.schemas import EvidenceSource, ThreatReputationInfo

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse


# Development offline threat reputation fixtures
OFFLINE_REPUTATION_FIXTURES = {
    "203.0.113.88": {
        "score": 85.0,
        "malicious": 14,
        "suspicious": 6,
        "total": 88,
        "verdict": "MALICIOUS",
        "blacklist": ["AbuseIPDB Confirmed Malicious", "Spamhaus ZEN", "Emerging Threats Botnet"],
    },
    "185.220.101.5": {
        "score": 75.0,
        "malicious": 8,
        "suspicious": 12,
        "total": 88,
        "verdict": "SUSPICIOUS",
        "blacklist": ["Tor Exit Node Active List", "Blocklist.de SSH/Mail"],
    },
    "198.51.100.45": {
        "score": 80.0,
        "malicious": 11,
        "suspicious": 5,
        "total": 88,
        "verdict": "MALICIOUS",
        "blacklist": ["PhishTank Known Drop", "SURBL Phishing Feed"],
    },
    "http://198.51.100.45/portal/login.php?session=928472910": {
        "score": 90.0,
        "malicious": 18,
        "suspicious": 4,
        "total": 92,
        "verdict": "MALICIOUS",
        "blacklist": ["OpenPhish Active Feed", "PhishTank Verified"],
    },
}


class BaseThreatIntelProvider(ABC):
    """Abstract interface for threat reputation intelligence providers."""

    @abstractmethod
    async def query_indicator(self, indicator: str, indicator_type: str) -> ThreatReputationInfo:
        pass


class OfflineThreatIntelProvider(BaseThreatIntelProvider):
    """Deterministic offline intelligence provider returning curated knowledge-base records."""

    async def query_indicator(self, indicator: str, indicator_type: str) -> ThreatReputationInfo:
        clean_ind = indicator.strip()
        now_iso = datetime.now(timezone.utc).isoformat()

        if clean_ind in OFFLINE_REPUTATION_FIXTURES:
            f = OFFLINE_REPUTATION_FIXTURES[clean_ind]
            return ThreatReputationInfo(
                indicator=clean_ind,
                indicator_type=indicator_type,
                provider="DeepTrace Offline Threat Database (Fixture)",
                reputation_score=f["score"],
                malicious_votes=f["malicious"],
                suspicious_votes=f["suspicious"],
                total_engines=f["total"],
                blacklist_hits=f["blacklist"],
                verdict=f["verdict"],
                status="FIXTURE",
                last_checked=now_iso,
                source=EvidenceSource.OFFLINE_FIXTURE.value,
            )

        return ThreatReputationInfo(
            indicator=clean_ind,
            indicator_type=indicator_type,
            provider="DeepTrace Intelligence Aggregator",
            reputation_score=0.0,
            malicious_votes=0,
            suspicious_votes=0,
            total_engines=0,
            blacklist_hits=[],
            verdict="UNKNOWN",
            status="UNAVAILABLE",
            last_checked=now_iso,
            source=EvidenceSource.OFFLINE_FIXTURE.value,
        )


class LiveAbuseIPDBProvider(BaseThreatIntelProvider):
    """Live provider querying AbuseIPDB REST API with safe timeouts and fallbacks."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.timeout = settings.HTTP_INTEL_TIMEOUT_SECONDS

    async def query_indicator(self, indicator: str, indicator_type: str) -> ThreatReputationInfo:
        clean_ind = indicator.strip()
        now_iso = datetime.now(timezone.utc).isoformat()

        if indicator_type == "IP" and not classify_ip(clean_ind).get("is_public"):
            return ThreatReputationInfo(indicator=clean_ind, indicator_type=indicator_type, provider="Local IP classification", verdict="UNKNOWN", status="SPECIAL_USE_IP", last_checked=now_iso)
        if indicator_type == "IP" and self.api_key:
            try:
                headers = {"Key": self.api_key, "Accept": "application/json"}
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={clean_ind}&maxAgeInDays=90"
                from backend.app.intelligence.http_client import provider_json
                code, payload = await provider_json(url, headers)
                if code == 200:
                    data = payload.get("data", {})
                    score = float(data.get("abuseConfidenceScore", 0))
                    verdict = "MALICIOUS" if score >= 60 else ("SUSPICIOUS" if score >= 20 else "NO_KNOWN_MATCH")
                    return ThreatReputationInfo(
                        indicator=clean_ind,
                        indicator_type="IP",
                        provider="AbuseIPDB Threat Feed",
                        reputation_score=score,
                        malicious_votes=int(data.get("totalReports", 0)),
                        total_engines=1,
                        blacklist_hits=[f"AbuseScore: {score}%", f"Reports: {data.get('totalReports', 0)}"],
                        verdict=verdict,
                        status="AVAILABLE",
                        last_checked=now_iso,
                        source=EvidenceSource.THREAT_INTEL.value,
                    )
                elif code == 429:
                    return ThreatReputationInfo(indicator=clean_ind, indicator_type=indicator_type, provider="AbuseIPDB", verdict="UNKNOWN", status="RATE_LIMITED", last_checked=now_iso)
                else:
                    logger.warning(f"AbuseIPDB returned status {code} for {clean_ind}")
            except Exception as e:
                logger.warning(f"AbuseIPDB live lookup exception for {clean_ind}: {e}")

        return ThreatReputationInfo(indicator=clean_ind, indicator_type=indicator_type, provider="AbuseIPDB", verdict="UNKNOWN", status="UNAVAILABLE", last_checked=now_iso, limitations=["Provider unavailable or indicator type unsupported"])


class ThreatIntelAdapter:
    """Adapter selecting active threat intelligence provider based on runtime settings."""

    @staticmethod
    def get_provider(mode: Optional[str] = None) -> BaseThreatIntelProvider:
        active_mode = (mode or settings.INTELLIGENCE_MODE).lower()
        if active_mode == "live":
            return LiveAbuseIPDBProvider()
        return OfflineThreatIntelProvider()


class ThreatReputationService:
    """Manages multi-provider threat intelligence and reputation enrichment across observables."""

    def __init__(self, provider: Optional[BaseThreatIntelProvider] = None, mode: Optional[str] = None):
        self.mode = mode or settings.INTELLIGENCE_MODE.lower()
        self.provider = provider or ThreatIntelAdapter.get_provider(self.mode)

    async def query_indicator(self, indicator: str, indicator_type: str) -> ThreatReputationInfo:
        """Query reputation for an IP, domain, URL, or hash with guaranteed non-blocking fallback."""
        try:
            return await self.provider.query_indicator(indicator, indicator_type)
        except Exception as e:
            logger.warning(f"Threat reputation provider error for {indicator} ({e}); falling back to offline.")
            return ThreatReputationInfo(indicator=indicator, indicator_type=indicator_type, verdict="UNKNOWN", status="ERROR", last_checked=datetime.now(timezone.utc).isoformat())

    async def enrich_observables(self, analysis: EmailAnalysisResponse) -> Dict[str, ThreatReputationInfo]:
        """Query threat intelligence for key observables in email."""
        results: Dict[str, ThreatReputationInfo] = {}

        # 1. Check Origin / Public IPs
        for ip_item in analysis.ips:
            if ip_item.is_public:
                res = await self.query_indicator(ip_item.ip, "IP")
                results[ip_item.ip] = res

        # 2. Check Suspicious URLs
        for url_item in analysis.urls:
            if url_item.is_ip_host or url_item.is_shortener:
                res = await self.query_indicator(url_item.url, "URL")
                results[url_item.url] = res

        return results
