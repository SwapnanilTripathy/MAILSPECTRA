<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:89ebe872d455e139e2a58576eb59a342cf008b18182220247443897ef7bf1ed0 -->

<!-- coderabbit-ai-generated-section:v1:6817f17b4c9e42fa3e9645feb445e267e733928fead18b53017a564343187aef -->

# Email forensics methodology

Only RFC 5322/MIME `.eml` uploads and explicit raw-message text are supported. Outlook `.msg` is rejected. Both input paths enforce the configured byte limit and reject missing/malformed message headers. Filenames are metadata, never storage paths. Attachments are hashed and statically inspected (extension, simple signature, double extension); nothing is executed or fetched.

The parser retains duplicate raw headers alongside decoded display values, MIME structure, original digests, URL/IP source locations and attachment metadata. Received headers are reversed into transmission order; timestamps without a timezone are unknown and negative/large deltas are anomalies, not proof of an attack. `TRUSTED_RECEIVERS` marks a configured receiver claim; uploaded text alone cannot establish trusted acquisition. Documentation, shared-address, reserved and other non-global IP ranges are not public infrastructure. A private fallback hop is explicitly not a public origin.

Authentication fields `spf_result`/`dkim_result`/`dmarc_result` remain reported header claims for compatibility. `reported_status` labels them untrusted. `verified` contains independent results separately. DNS verification defaults off. With `VERIFY_AUTHENTICATION_DNS=true`, dkimpy verifies up to five DKIM signatures and current DNS keys; DMARC alignment uses those verified domains and retrieved policy. DNS uses bounded timeouts. Historical keys/policies may differ from delivery time.

The pyspf adapter accepts trusted SMTP peer, envelope sender and HELO metadata. Saved-message ingestion does not invent those values from headers, so its SPF result is unavailable. When DNS verification is enabled, dkimpy independently verifies ARC chains with a ten-set work limit. A valid chain does not establish trust in its sealing operators or authenticate the original sender; current DNS keys may differ from delivery-time keys. DMARC cannot fail conclusively when an independent mechanism needed for alignment is unavailable.

Tests include locally signed ARC chains, tampered ARC bodies, chain budget enforcement, a locally signed DKIM message and tampered body with synthetic DNS, reported-header forgery, duplicate recipient headers, non-public IPv4/IPv6 ranges, unavailable SPF and DMARC alignment. Independent live DNS behavior is not established by these tests.


<!-- /coderabbit-ai-generated:v1 -->