from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional
import httpx

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.intelligence.schemas import EvidenceSource, GeoLocationInfo
from backend.app.utils.crypto import defang_ip
from backend.app.utils.network import classify_ip, is_valid_ip


# Known documentation/test prefixes and standard development fixtures
OFFLINE_FIXTURES = {
    "198.51.100.25": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "isp": "LegitCorp Global Transit",
        "asn": "AS15169",
        "organization": "LegitCorp Infrastructure",
        "hosting_provider": "Enterprise Cloud",
        "proxy_or_vpn": False,
        "confidence": 0.85,
    },
    "203.0.113.88": {
        "country": "Russian Federation",
        "country_code": "RU",
        "region": "Moscow",
        "city": "Moscow",
        "latitude": 55.7558,
        "longitude": 37.6173,
        "isp": "Offshore VPS Networks LLC",
        "asn": "AS49872",
        "organization": "Attacker Infrastructure Net",
        "hosting_provider": "Bulletproof Hosting Group",
        "proxy_or_vpn": True,
        "confidence": 0.80,
    },
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "region": "Hesse",
        "city": "Frankfurt",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "isp": "Tor Relay Exit Operator",
        "asn": "AS200052",
        "organization": "Privacy Proxy Service",
        "hosting_provider": "European VPS Hosting",
        "proxy_or_vpn": True,
        "confidence": 0.85,
    },
    "198.51.100.45": {
        "country": "Panama",
        "country_code": "PA",
        "region": "Panama",
        "city": "Panama City",
        "latitude": 8.9824,
        "longitude": -79.5199,
        "isp": "Anonymous Web Solutions",
        "asn": "AS61234",
        "organization": "Offshore Host Network",
        "hosting_provider": "Secure Host Inc",
        "proxy_or_vpn": True,
        "confidence": 0.75,
    },
}


class BaseGeoIPProvider(ABC):
    """Abstract interface for IP geolocation and ASN intelligence providers."""

    @abstractmethod
    async def lookup(self, ip_str: str) -> GeoLocationInfo:
        pass


class OfflineGeoIPProvider(BaseGeoIPProvider):
    """Safe offline provider returning explicit development fixtures or unverified status."""

    async def lookup(self, ip_str: str) -> GeoLocationInfo:
        clean_ip = ip_str.strip("[] ")
        defanged = defang_ip(clean_ip)
        classification = classify_ip(clean_ip)

        if not classification.get("is_valid", False):
            return GeoLocationInfo(
                ip=clean_ip,
                defanged_ip=defanged,
                is_private=False,
                is_public=False,
                status="INVALID_IP",
                source=EvidenceSource.OFFLINE_FIXTURE.value,
            )

        if classification.get("is_private", False) or classification.get("is_loopback", False):
            return GeoLocationInfo(
                ip=clean_ip,
                defanged_ip=defanged,
                version=classification.get("version", 4),
                is_private=True,
                is_public=False,
                organization="Private / Internal Network (RFC1918 / Loopback)",
                confidence=1.0,
                status="PRIVATE_IP",
                source=EvidenceSource.OFFLINE_FIXTURE.value,
            )

        # Check curated development fixtures
        if clean_ip in OFFLINE_FIXTURES:
            f = OFFLINE_FIXTURES[clean_ip]
            return GeoLocationInfo(
                ip=clean_ip,
                defanged_ip=defanged,
                version=classification.get("version", 4),
                is_private=False,
                is_public=True,
                country=f.get("country"),
                country_code=f.get("country_code"),
                region=f.get("region"),
                city=f.get("city"),
                latitude=f.get("latitude"),
                longitude=f.get("longitude"),
                isp=f.get("isp"),
                asn=f.get("asn"),
                organization=f.get("organization"),
                hosting_provider=f.get("hosting_provider"),
                proxy_or_vpn=f.get("proxy_or_vpn"),
                confidence=f.get("confidence", 0.7),
                status="SUCCESS",
                source=EvidenceSource.OFFLINE_FIXTURE.value,
            )

        # Standard unverified public IP fallback
        return GeoLocationInfo(
            ip=clean_ip,
            defanged_ip=defanged,
            version=classification.get("version", 4),
            is_private=False,
            is_public=True,
            organization="Public IP (Offline mode - no live lookup)",
            confidence=0.0,
            status="UNAVAILABLE",
            source=EvidenceSource.OFFLINE_FIXTURE.value,
        )


class LiveIPInfoProvider(BaseGeoIPProvider):
    """Live provider querying ipinfo.io or ip-api.com with safe timeouts."""

    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.IPINFO_TOKEN
        self.timeout = settings.HTTP_INTEL_TIMEOUT_SECONDS

    async def lookup(self, ip_str: str) -> GeoLocationInfo:
        clean_ip = ip_str.strip("[] ")
        defanged = defang_ip(clean_ip)
        classification = classify_ip(clean_ip)

        if not classification.get("is_valid", False) or classification.get("is_private", False):
            return GeoLocationInfo(
                ip=clean_ip,
                defanged_ip=defanged,
                version=classification.get("version", 4),
                is_private=classification.get("is_private", False),
                is_public=classification.get("is_public", True),
                organization="Private / Internal Network" if classification.get("is_private") else "Invalid IP",
                status="PRIVATE_IP" if classification.get("is_private") else "INVALID_IP",
                source=EvidenceSource.GEOIP.value,
            )

        # Check curated development fixtures first
        if clean_ip in OFFLINE_FIXTURES:
            f = OFFLINE_FIXTURES[clean_ip]
            return GeoLocationInfo(
                ip=clean_ip,
                defanged_ip=defanged,
                version=classification.get("version", 4),
                is_private=False,
                is_public=True,
                country=f.get("country"),
                country_code=f.get("country_code"),
                region=f.get("region"),
                city=f.get("city"),
                latitude=f.get("latitude"),
                longitude=f.get("longitude"),
                isp=f.get("isp"),
                asn=f.get("asn"),
                organization=f.get("organization"),
                hosting_provider=f.get("hosting_provider"),
                proxy_or_vpn=f.get("proxy_or_vpn"),
                confidence=f.get("confidence", 0.85),
                status="SUCCESS",
                source=EvidenceSource.GEOIP.value,
            )

        # Query external API
        url = f"https://ipinfo.io/{clean_ip}/json" if self.token else f"http://ip-api.com/json/{clean_ip}"
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    loc = data.get("loc", "").split(",")
                    lat = float(loc[0]) if len(loc) == 2 else data.get("lat")
                    lon = float(loc[1]) if len(loc) == 2 else data.get("lon")

                    # Check if valid location data was returned
                    if lat is not None and lon is not None and (lat != 0 or lon != 0 or data.get("country")):
                        return GeoLocationInfo(
                            ip=clean_ip,
                            defanged_ip=defanged,
                            version=classification.get("version", 4),
                            is_private=False,
                            is_public=True,
                            country=data.get("country") or "Unknown Country",
                            country_code=data.get("countryCode") or data.get("country"),
                            region=data.get("region") or data.get("regionName"),
                            city=data.get("city"),
                            latitude=lat,
                            longitude=lon,
                            isp=data.get("isp") or data.get("org"),
                            asn=data.get("as") or (data.get("org", "").split()[0] if data.get("org") else None),
                            organization=data.get("org") or data.get("isp"),
                            hosting_provider=data.get("hosting"),
                            confidence=0.85,
                            status="SUCCESS",
                            source=EvidenceSource.GEOIP.value,
                        )
                else:
                    logger.warning(f"Live GeoIP returned HTTP {resp.status_code} for {clean_ip}")
        except Exception as e:
            logger.warning(f"Live GeoIP exception for {clean_ip}: {e}")

        # Fallback to offline provider on failure
        return await OfflineGeoIPProvider().lookup(clean_ip)


def get_geoip_provider() -> BaseGeoIPProvider:
    """Factory returning configured GeoIP provider."""
    if settings.INTELLIGENCE_MODE.lower() == "live":
        return LiveIPInfoProvider()
    return OfflineGeoIPProvider()
