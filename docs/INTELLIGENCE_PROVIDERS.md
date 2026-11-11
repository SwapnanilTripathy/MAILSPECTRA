<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:4055a8c5dbab39c3c3b787904d867f5a3dd078e8c6f943e0afac7df71fdb33be -->

<!-- coderabbit-ai-generated-section:v1:fa14d2d2ef18a3f7670edc528089a0b9bf753b8ff71261c56cdf8beba5cdbc69 -->

# Intelligence providers and disclosure

`INTELLIGENCE_MODE=offline` is the safe default. Offline data is explicitly `OFFLINE_FIXTURE`/`FIXTURE`; missing entries are `UNAVAILABLE`/`UNKNOWN`, never clean. Fixtures are not external observations. Live mode selects actual adapters and never substitutes fixtures on failure.

Implemented: AbuseIPDB IP reputation, ipapi.is and legacy IPInfo GeoIP adapters, DNS and RDAP. The IOC workbench now supports VirusTotal existing IP/domain/URL/file-hash reports and Shodan IP host observations. Select a provider explicitly or use Automatic (AbuseIPDB for IPs, VirusTotal for other types). Shodan observations are not a maliciousness verdict. No scans or submissions are performed. Credentialed requests reject redirects; status distinguishes missing credentials, authentication errors, absent reports, rate limits and malformed responses. Provider credentials and live results remain unverified. IPInfo requires its token; no plaintext HTTP fallback is used. AbuseIPDB represents one provider, not 100 independent engines. A completed lookup with score zero is `NO_KNOWN_MATCH`, not a safety guarantee. Special-use IPs are not sent to live providers.


### Live GeoIP: ipapi.is

`GEOIP_PROVIDER=ipapi.is` selects the ipapi.is adapter when `INTELLIGENCE_MODE=live`. Configure `IPAPI_IS_KEY` only in the backend environment. The adapter sends a single-IP lookup as a JSON `POST` body so the API key is not placed in the URL, and the provider host is explicitly allowlisted. ipapi.is documents a keyed free tier and returns ASN/company, location, hosting, and network classification signals; see its [API documentation](https://ipapi.is/developers.html) for current limits and fields.

The adapter accepts only globally routable addresses. Private, loopback, link-local, multicast, reserved, and documentation ranges are handled locally and are never disclosed to the provider. Provider errors, authentication failures, timeouts, and rate limits remain explicit statuses; live failures never fall back to development fixtures. The response IP is checked against the requested IP before any fields are accepted.

`is_vpn`, `is_proxy`, `is_tor`, `is_datacenter`, and `is_abuser` are preserved as separate provider observations. `proxy_or_vpn` is only a convenience aggregate; `is_abuser` is not a definitive maliciousness verdict. The adapter does not assign a calibrated location-confidence score, so `confidence` remains `0.0` and limitations explain that geolocation describes infrastructure/registration context, not a person's physical location or identity. Location may be absent or approximate, and residential proxies may not be detected by provider datasets.

To retain the legacy provider, set `GEOIP_PROVIDER=ipinfo` and configure `IPINFO_TOKEN`. The repository `.env.example` opts into `ipapi.is`. Existing deployments that omit `GEOIP_PROVIDER` retain the legacy `ipinfo` selection for compatibility. External lookups remain disabled unless `INTELLIGENCE_MODE=live` is explicitly enabled.

HTTP requests are HTTPS-only to allowlisted provider hosts, with timeouts, at most two redirects, credentials stripped on redirect, and a 1 MiB response cap. RDAP registries outside the explicit allowlist return unavailable/error rather than following arbitrary hosts. DNS queries are bounded; infrastructure enrichment has a 30-second total budget. TTL caching in the IOC workbench preserves lookup timestamps and exposes cache hits; unavailable/error/rate-limit outcomes are not cached as successful results.

`POST /api/v1/intelligence/lookup` validates IP/domain/URL/hash input and calls the configured reputation provider. VirusTotal handles domain/URL/hash reports in live mode; missing credentials or reports return unavailable. Entropy is returned as a separate local measurement. It is not DGA proof. No extracted URL or attachment is fetched/executed. Live configuration discloses indicators to the provider; never enable it for private evidence without organizational authorization.

Tests cover invalid inputs, offline absence, special-use IP exclusion, fixture labels, 429 responses, no-match results and cache timestamps. CodeRabbit emulate v0.0.1 was installed and its catalog inspected: it has no AbuseIPDB, IPInfo, DNS or RDAP emulators. Mocked provider checks establish adapter handling, not live account/quota/terms validation. Live provider validation requires appropriate credentials and deployment authorization.


<!-- /coderabbit-ai-generated:v1 -->