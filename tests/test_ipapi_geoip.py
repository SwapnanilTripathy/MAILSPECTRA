import httpx
import pytest

from backend.app.core.config import settings
from backend.app.intelligence.geoip import LiveIPAPIProvider, OfflineGeoIPProvider, get_geoip_provider


def sample_response(ip="8.8.8.8"):
    return {
        "ip": ip,
        "is_bogon": False,
        "is_datacenter": True,
        "is_vpn": False,
        "is_proxy": True,
        "is_tor": False,
        "is_abuser": True,
        "datacenter": {"datacenter": "Example Cloud"},
        "company": {"name": "Example Networks"},
        "asn": {"asn": 15169, "org": "Example ASN", "type": "hosting"},
        "location": {
            "country": "United States",
            "country_code": "US",
            "state": "California",
            "city": "Mountain View",
            "latitude": 37.4,
            "longitude": -122.1,
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "224.0.0.1",
        "192.0.2.10",
        "198.51.100.25",
        "203.0.113.88",
        "2001:db8::1",
        "not-an-ip",
    ],
)
async def test_ipapi_never_sends_non_global_or_invalid_addresses(address, monkeypatch):
    async def forbidden(*args, **kwargs):
        pytest.fail("Non-global or invalid IP must never leave the process")

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", forbidden)
    result = await LiveIPAPIProvider(api_key="test-key").lookup(address)
    assert result.status in {"INVALID_IP", "PRIVATE_IP", "SPECIAL_USE_IP"}
    assert result.country is None


@pytest.mark.asyncio
async def test_missing_key_is_unavailable_without_network(monkeypatch):
    async def forbidden(*args, **kwargs):
        pytest.fail("Missing credentials must not trigger a network request")

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", forbidden)
    result = await LiveIPAPIProvider(api_key="").lookup("8.8.8.8")
    assert result.status == "UNAVAILABLE"
    assert result.provider == "ipapi.is"


@pytest.mark.asyncio
async def test_ipapi_post_response_maps_network_and_location_fields(monkeypatch):
    calls = []

    async def response(url, headers=None, **kwargs):
        calls.append((url, headers, kwargs))
        return 200, sample_response()

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", response)
    result = await LiveIPAPIProvider(api_key="secret-test-key").lookup("8.8.8.8")

    assert result.status == "SUCCESS"
    assert result.provider == "ipapi.is"
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.region == "California"
    assert result.city == "Mountain View"
    assert result.asn == "AS15169"
    assert result.organization == "Example Networks"
    assert result.isp == "Example ASN"
    assert result.hosting_provider == "Example Cloud"
    assert result.is_datacenter is True
    assert result.is_vpn is False
    assert result.is_proxy is True
    assert result.is_tor is False
    assert result.is_abuser is True
    assert result.proxy_or_vpn is True
    assert result.confidence == 0.0
    assert calls[0][0] == "https://api.ipapi.is"
    assert calls[0][2]["method"] == "POST"
    assert calls[0][2]["json_body"] == {"q": "8.8.8.8", "key": "secret-test-key"}
    assert calls[0][2]["allow_redirects"] is False


@pytest.mark.asyncio
async def test_ipapi_response_ip_mismatch_is_rejected(monkeypatch):
    async def response(*args, **kwargs):
        return 200, sample_response(ip="1.1.1.1")

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", response)
    result = await LiveIPAPIProvider(api_key="test-key").lookup("8.8.8.8")
    assert result.status == "ERROR"
    assert result.country is None


@pytest.mark.asyncio
async def test_ipapi_malformed_nested_response_is_unknown_not_success(monkeypatch):
    async def response(*args, **kwargs):
        payload = sample_response()
        payload["location"] = "unexpected"
        return 200, payload

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", response)
    result = await LiveIPAPIProvider(api_key="test-key").lookup("8.8.8.8")
    assert result.status == "ERROR"
    assert result.is_abuser is None


@pytest.mark.asyncio
async def test_ipapi_bogon_response_suppresses_location(monkeypatch):
    async def response(*args, **kwargs):
        payload = sample_response()
        payload["is_bogon"] = True
        return 200, payload

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", response)
    result = await LiveIPAPIProvider(api_key="test-key").lookup("8.8.8.8")
    assert result.status == "SPECIAL_USE_IP"
    assert result.country is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,expected",
    [(401, "AUTH_ERROR"), (403, "AUTH_ERROR"), (429, "RATE_LIMITED"), (500, "ERROR")],
)
async def test_ipapi_http_failure_states(code, expected, monkeypatch):
    async def response(*args, **kwargs):
        return code, {}

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", response)
    result = await LiveIPAPIProvider(api_key="test-key").lookup("8.8.8.8")
    assert result.status == expected
    assert result.country is None


@pytest.mark.asyncio
async def test_ipapi_timeout_is_reported_without_fixture_fallback(monkeypatch):
    async def timeout(*args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("backend.app.intelligence.http_client.provider_json", timeout)
    result = await LiveIPAPIProvider(api_key="test-key").lookup("8.8.8.8")
    assert result.status == "TIMEOUT"
    assert result.source != "OFFLINE_FIXTURE"
    assert result.country is None


def test_geoip_factory_uses_explicit_provider_selection(monkeypatch):
    monkeypatch.setattr(settings, "INTELLIGENCE_MODE", "live")
    monkeypatch.setattr(settings, "GEOIP_PROVIDER", "ipapi.is")
    assert isinstance(get_geoip_provider(), LiveIPAPIProvider)

    monkeypatch.setattr(settings, "GEOIP_PROVIDER", "ipinfo")
    assert get_geoip_provider().__class__.__name__ == "LiveIPInfoProvider"

    monkeypatch.setattr(settings, "GEOIP_PROVIDER", "unknown-provider")
    assert isinstance(get_geoip_provider(), OfflineGeoIPProvider)
