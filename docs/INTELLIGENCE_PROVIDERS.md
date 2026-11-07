<!-- coderabbit-ai-generated:v1 -->

# Intelligence providers and disclosure

`INTELLIGENCE_MODE=offline` is the safe default. Offline data is explicitly `OFFLINE_FIXTURE`/`FIXTURE`; missing entries are `UNAVAILABLE`/`UNKNOWN`, never clean. Fixtures are not external observations. Live mode selects actual adapters and never substitutes fixtures on failure.

Implemented: AbuseIPDB IP reputation, IPInfo GeoIP, DNS and RDAP. VirusTotal and Shodan configuration do not constitute implementations; system settings label them unimplemented. IPInfo requires its token; no plaintext HTTP fallback is used. AbuseIPDB represents one provider, not 100 independent engines. A completed lookup with score zero is `NO_KNOWN_MATCH`, not a safety guarantee. Special-use IPs are not sent to live providers.

HTTP requests are HTTPS-only to allowlisted provider hosts, with timeouts, at most two redirects, credentials stripped on redirect, and a 1 MiB response cap. RDAP registries outside the explicit allowlist return unavailable/error rather than following arbitrary hosts. DNS queries are bounded; infrastructure enrichment has a 30-second total budget. TTL caching in the IOC workbench preserves lookup timestamps and exposes cache hits; unavailable/error/rate-limit outcomes are not cached as successful results.

`POST /api/v1/intelligence/lookup` validates IP/domain/URL/hash input and calls the configured reputation provider. Unsupported domain/URL/hash reputation is unavailable; entropy is returned as a separate local measurement. It is not DGA proof. No extracted URL or attachment is fetched/executed. Live configuration discloses indicators to the provider; never enable it for private evidence without organizational authorization.

Tests cover invalid inputs, offline absence, special-use IP exclusion, fixture labels, 429 responses, no-match results and cache timestamps. CodeRabbit emulate v0.0.1 was installed and its catalog inspected: it has no AbuseIPDB, IPInfo, DNS or RDAP emulators. Mocked provider checks establish adapter handling, not live account/quota/terms validation. Live provider validation requires appropriate credentials and deployment authorization.
