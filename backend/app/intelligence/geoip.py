from abc import ABC, abstractmethod
import ipaddress
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
                is_public=classification["is_public"],
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
                status="FIXTURE",
                source=EvidenceSource.OFFLINE_FIXTURE.value,
            )

        # Standard unverified public IP fallback
        return GeoLocationInfo(
            ip=clean_ip,
            defanged_ip=defanged,
            version=classification.get("version", 4),
            is_private=False,
            is_public=classification["is_public"],
            organization="Offline mode - no live lookup",
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

        if not classification.get("is_public"):
            return GeoLocationInfo(ip=clean_ip, defanged_ip=defanged, is_public=False, status="SPECIAL_USE_IP")
        if not self.token:
            return GeoLocationInfo(ip=clean_ip, defanged_ip=defanged, status="UNAVAILABLE", limitations=["IPInfo credentials are not configured"])

        # Query external API
        url = f"https://ipinfo.io/{clean_ip}/json"
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}

        try:
            from backend.app.intelligence.http_client import provider_json
            code, data = await provider_json(url, headers)
            if code == 200:
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
                logger.warning("GeoIP returned HTTP %s", code)
        except Exception as e:
            logger.warning("GeoIP failed: %s", type(e).__name__)

        return GeoLocationInfo(ip=clean_ip, defanged_ip=defanged, status="ERROR", limitations=["Live provider failed; no fixture substituted"])


class LiveIPAPIProvider(BaseGeoIPProvider):
    """Live GeoIP and network-context provider backed by ipapi.is."""

    endpoint = "https://api.ipapi.is"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else settings.IPAPI_IS_KEY

    @staticmethod
    def _flag(value):
        # ipapi.is documents is_vpn as truthy rather than strictly boolean.
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() not in {"", "0", "false", "no", "none"}
        return None

    @staticmethod
    def _number(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    async def lookup(self, ip_str: str) -> GeoLocationInfo:
        clean_ip = ip_str.strip("[] ")
        defanged = defang_ip(clean_ip)
        classification = classify_ip(clean_ip)

        if not classification.get("is_valid", False):
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, is_public=False,
                status="INVALID_IP", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
            )

        if not classification.get("is_public", False):
            is_private = bool(
                classification.get("is_private") or classification.get("is_loopback")
            )
            return GeoLocationInfo(
                ip=clean_ip,
                defanged_ip=defanged,
                version=classification.get("version", 4),
                is_private=is_private,
                is_public=False,
                status="PRIVATE_IP" if is_private else "SPECIAL_USE_IP",
                provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["Non-global IP addresses are not sent to external GeoIP providers"],
            )

        if not self.api_key:
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged,
                version=classification.get("version", 4),
                is_private=False, is_public=True,
                status="UNAVAILABLE", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["IPAPI_IS_KEY is not configured; keyed lookups are required for security flags"],
            )

        try:
            from backend.app.intelligence.http_client import provider_json

            code, data = await provider_json(
                self.endpoint,
                headers={"Accept": "application/json"},
                method="POST",
                json_body={"q": clean_ip, "key": self.api_key},
                allow_redirects=False,
            )
        except httpx.TimeoutException:
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, version=classification.get("version", 4),
                is_public=True, status="TIMEOUT", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["ipapi.is lookup timed out; no fixture substituted"],
            )
        except Exception as exc:
            logger.warning("ipapi.is GeoIP request failed: %s", type(exc).__name__)
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, version=classification.get("version", 4),
                is_public=True, status="ERROR", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["ipapi.is request failed; no fixture substituted"],
            )

        if code in {401, 403}:
            status = "AUTH_ERROR"
        elif code == 429:
            status = "RATE_LIMITED"
        elif code != 200:
            status = "ERROR"
        else:
            status = "SUCCESS"

        if status != "SUCCESS":
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, version=classification.get("version", 4),
                is_public=True, status=status, provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["ipapi.is did not return a usable lookup; no fixture substituted"],
            )

        if not isinstance(data, dict) or data.get("error"):
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, version=classification.get("version", 4),
                is_public=True, status="ERROR", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["ipapi.is returned an error or malformed response"],
            )

        returned_ip = data.get("ip")
        try:
            if not isinstance(returned_ip, str) or ipaddress.ip_address(returned_ip) != ipaddress.ip_address(clean_ip):
                raise ValueError("Provider response IP does not match request")
        except ValueError:
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, version=classification.get("version", 4),
                is_public=True, status="ERROR", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["Provider response IP did not match the requested address"],
            )

        if data.get("is_bogon") is True:
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, version=classification.get("version", 4),
                is_public=False, status="SPECIAL_USE_IP", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["Provider classified the address as bogon; location was suppressed"],
            )

        location = data.get("location")
        company = data.get("company")
        asn_data = data.get("asn")
        datacenter = data.get("datacenter")
        if any(value is not None and not isinstance(value, dict) for value in (location, company, asn_data, datacenter)):
            return GeoLocationInfo(
                ip=clean_ip, defanged_ip=defanged, version=classification.get("version", 4),
                is_public=True, status="ERROR", provider="ipapi.is",
                source=EvidenceSource.GEOIP.value,
                limitations=["ipapi.is returned an unexpected nested response shape"],
            )

        location = location or {}
        company = company or {}
        asn_data = asn_data or {}
        datacenter = datacenter or {}

        lat = self._number(location.get("latitude"))
        lon = self._number(location.get("longitude"))
        if lat is not None and not -90 <= lat <= 90:
            lat = None
        if lon is not None and not -180 <= lon <= 180:
            lon = None

        vpn = self._flag(data.get("is_vpn"))
        proxy = self._flag(data.get("is_proxy"))
        tor = self._flag(data.get("is_tor"))
        datacenter_flag = self._flag(data.get("is_datacenter"))
        abuser = self._flag(data.get("is_abuser"))
        proxy_or_vpn = None if None in (vpn, proxy, tor) else bool(vpn or proxy or tor)

        asn_value = asn_data.get("asn")
        if isinstance(asn_value, int) and not isinstance(asn_value, bool):
            asn = f"AS{asn_value}"
        elif isinstance(asn_value, str):
            asn = asn_value if asn_value.upper().startswith("AS") else f"AS{asn_value}"
        else:
            asn = None

        organization = company.get("name") or asn_data.get("org")
        hosting_provider = datacenter.get("datacenter")
        limitations = [
            "GeoIP describes network infrastructure or registration context, not a person's physical location or identity",
            "Location precision varies by provider data and network type",
        ]
        if lat is None or lon is None:
            limitations.append("Provider did not return valid coordinates")

        return GeoLocationInfo(
            ip=clean_ip,
            defanged_ip=defanged,
            version=classification.get("version", 4),
            is_private=False,
            is_public=True,
            country=location.get("country") if isinstance(location.get("country"), str) else None,
            country_code=location.get("country_code") if isinstance(location.get("country_code"), str) else None,
            region=location.get("state") if isinstance(location.get("state"), str) else None,
            city=location.get("city") if isinstance(location.get("city"), str) else None,
            latitude=lat,
            longitude=lon,
            isp=asn_data.get("org") if isinstance(asn_data.get("org"), str) else organization,
            asn=asn,
            organization=organization if isinstance(organization, str) else None,
            hosting_provider=hosting_provider if isinstance(hosting_provider, str) else None,
            proxy_or_vpn=proxy_or_vpn,
            is_datacenter=datacenter_flag,
            is_vpn=vpn,
            is_proxy=proxy,
            is_tor=tor,
            is_abuser=abuser,
            confidence=0.0,
            provider="ipapi.is",
            status="SUCCESS",
            source=EvidenceSource.GEOIP.value,
            limitations=limitations,
        )


def get_geoip_provider() -> BaseGeoIPProvider:
    """Factory returning the explicitly selected GeoIP provider."""
    if settings.INTELLIGENCE_MODE.lower() != "live":
        return OfflineGeoIPProvider()
    selected = settings.GEOIP_PROVIDER.strip().lower()
    if selected == "ipapi.is":
        return LiveIPAPIProvider()
    if selected == "ipinfo":
        return LiveIPInfoProvider()
    logger.warning("Unsupported GEOIP_PROVIDER %r; keeping GeoIP offline", selected)
    return OfflineGeoIPProvider()
