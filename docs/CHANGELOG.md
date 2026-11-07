<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:075158114926c758c882fa5d9edb5e703630ec8b7b8603f70457471024b8888d -->

# Changelog

## Specification implementation — November 2026

- Phase 0: documented inherited baseline and contract defects.
- Phase 1: replaced demo authentication with scrypt, signed sessions, revocation, roles and persistent login throttling.
- Phase 2: aligned backend/frontend schema, graph, relay, DNS, campaign and attachment bindings and added render checks.
- Phase 3: introduced additive Alembic migrations, original-byte storage, evidence manifests and hash verification.
- Phase 4: separated reported/verified authentication, added DKIM/SPF adapters and DMARC alignment, retained duplicate headers and corrected origin confidence.
- Phase 5: moved preprocessing inside training folds, separated holdout, documented model limitations and normalized canonical risk/classification.
- Phase 6: labelled synthetic/unavailable intelligence, bounded provider HTTP, added cache metadata and connected IOC lookup.
- Phase 7: added graph evidence references/inspection and cautious campaign correlation with shared indicators.
- Phase 8: persisted alert acknowledgement/resolution, masked views/reports, added report manifests and audit records.
- Phase 9: hardened deployment/health/logging/body limits, updated vulnerable dependencies, split frontend bundles, improved accessibility and documented operations.

Compatibility: private API clients must authenticate; .msg remains unsupported; production startup requires explicit migrations and a strong key. Risk scores intentionally change under the supplied specification; source bytes and legacy case records are preserved. Reports distinguish a recorded digest from a subsequently verified artifact. Inherited model and dataset limitations remain explicit.


<!-- /coderabbit-ai-generated:v1 -->