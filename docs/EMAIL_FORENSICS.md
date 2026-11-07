<!-- coderabbit-ai-generated:v1 -->

# Email forensics methodology

Only RFC 5322/MIME `.eml` uploads and explicit raw-message text are supported. Outlook `.msg` is rejected. Both input paths enforce the configured byte limit and reject missing/malformed message headers. Filenames are metadata, never storage paths. Attachments are hashed and statically inspected (extension, simple signature, double extension); nothing is executed or fetched.

The parser retains duplicate raw headers alongside decoded display values, MIME structure, original digests, URL/IP source locations and attachment metadata. Received headers are reversed into transmission order; timestamps without a timezone are unknown and negative/large deltas are anomalies, not proof of an attack. `TRUSTED_RECEIVERS` marks a configured receiver claim; uploaded text alone cannot establish trusted acquisition. Documentation, shared-address, reserved and other non-global IP ranges are not public infrastructure. A private fallback hop is explicitly not a public origin.

Authentication fields `spf_result`/`dkim_result`/`dmarc_result` remain reported header claims for compatibility. `reported_status` labels them untrusted. `verified` contains independent results separately. DNS verification defaults off. With `VERIFY_AUTHENTICATION_DNS=true`, dkimpy verifies up to five DKIM signatures and current DNS keys; DMARC alignment uses those verified domains and retrieved policy. DNS uses bounded timeouts. Historical keys/policies may differ from delivery time.

The pyspf adapter accepts trusted SMTP peer, envelope sender and HELO metadata. Saved-message ingestion does not invent those values from headers, so its SPF result is unavailable. ARC verification is deferred and labelled unavailable. DMARC cannot fail conclusively when an independent mechanism needed for alignment is unavailable.

Tests include a locally signed DKIM message and tampered body with synthetic DNS, reported-header forgery, duplicate recipient headers, non-public IPv4/IPv6 ranges, unavailable SPF and DMARC alignment. Independent live DNS behavior is not established by these tests.
