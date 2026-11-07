<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:089f11f691f16131394a2a9f251a6e1721faa4e01b7f615007f2a24e02e8adc7 -->

<!-- coderabbit-ai-generated-section:v1:3491ef07f83855b054a6445daf69ca97cc05803eb0adba39c9ec60277aa1a7b5 -->

<!-- coderabbit-ai-generated-section:v1:6dee5173e8f8451169cc6a582fb132d753c27caac5ffe51b4248e8c2a0bb6662 -->

<!-- coderabbit-ai-generated-section:v1:c678abb0770d7103660bf491a9b9b2ad3f8095eb64edfd5e5be55911bd63f5da -->

# Specification phase status

This records implementation of the owner's MAILSPECTRA coding specification. The owner authorized proceeding through all phases and pushing the work to `coderabbit/open-frontend-files/81a0d3ed`, then requested a push after each phase. Phases 1–8 were pushed together at bf22481 when that instruction arrived; Phase 9 is a separate final push. No changes were pushed to main.

“Implemented” describes delivered code and the checks below. It does not certify production readiness or resolve missing external evidence. **The specification cannot honestly be called unconditionally complete:** dataset rights/representativeness, live provider validation and external hosting acceptance remain open.

| Phase | Implementation / evidence | Remaining acceptance limits |
| --- | --- | --- |
| 0 — Baseline | `9d3aa63`; original baseline preserved in BASELINE_AUDIT.md. Final supplemental scan inspected 17 local-history commits and 308 unique blobs for four high-confidence credential formats; no matches. Original LICENSE unchanged. | Pattern scan is not a comprehensive secret/privacy audit. Inherited sample provenance remains unverified. |
| 1 — Auth | `2423a73`; scrypt, expiring signed sessions, revocation, roles, persistent login throttling, negative tests and authenticated downloads. Phase 9 replaces python-jose with PyJWT after vulnerability review. | Single-organization access; proxy concurrency/rate controls remain deployment responsibilities. |
| 2 — Contracts | `0b130bd`; canonical schemas/types, corrected panel bindings and render fixtures; generated declarations refreshed after graph changes. | Legacy snapshots can lack newly introduced evidence fields and are shown as unavailable. |
| 3 — Persistence | `7c19ec`; additive migrations, original artifacts, idempotent ingestion, snapshots, observations/audit and verification; migration/tamper tests. | No distributed filesystem/SQL transaction; reconcile interrupted writes. Legacy evidence cannot be reconstructed. |
| 4 — Forensics | `60e3b06`; duplicate headers, extraction provenance, IP classification, DKIM cryptographic verification, SPF adapter and verified-result DMARC alignment, conservative relay/origin handling. | Saved email does not supply a trusted SMTP envelope/peer. SPF is unavailable without it. ARC cryptographic verification is implemented in follow-up 5748708; operator trust remains separate. Live DNS verification was not exercised. |
| 5 — ML/risk | `8353473`; leakage-free fold preprocessing, grouped duplicates, independent holdout, manifest/metrics, bounded canonical scoring and labelled explanation methods. | Dataset licensing/labels are unverified; 21 messages are inadequate. Seven-message holdout accuracy 0.7143 and CV 0.1429 are not operational evidence. Model/rule feature correlation remains a calibration concern. |
| 6 — Intelligence | `e65f9d8`; provider status/source/freshness, bounded HTTPS, special-use filtering, TTL cache, backend IOC lookup and provider mock tests. | No live provider credentials validated. Emulate v0.0.1 has no matching adapters. VirusTotal/Shodan workbench adapters are implemented in follow-up 548e403. |
| 7 — Graph/campaign | `4217d36`; evidence references, observed/inferred relationships, graph metrics/filters/inspection, shared-value/time-window correlation and cautious attribution. | Campaign similarity is investigative support, not actor identity. Saved Received headers remain supplied claims. |
| 8 — Analyst workflow | `bf22481`; durable alerts, acknowledgement/resolution, reopen, masking, PDF/manifest/audit, two API end-to-end workflows. Final UI refinements included in Phase 9. | Masking is best effort. Viewer PDF generation remains disallowed; existing authorized report downloads are supported. |
| 9 — Deployment/hardening | Final implementation includes nonroot image, persistent storage, migration gate, readiness, request IDs/JSON logs, request byte limits, vulnerability remediation, bundle splitting, accessibility fixes and operator docs. | External hosting was not deployed. PostgreSQL 17 checks passed in follow-up 06a3dbf. Hosting disaster recovery remains unverified. Dependency license/use requirements need operator review. |

## Verification evidence

- Backend: **110 tests passed** in the complete suite after request/report hardening; **13 affected API/hardening/end-to-end tests passed** after the final system-status adjustment. Synthetic data and isolated offline SQLite were used.
- Frontend: privacy regression test and **six contract render checks**, plus production build. Large pages are split into lazy-loaded chunks. A temporary heading-tag build error was fixed before the final build.
- Dependency audits: npm and pip reported **zero known vulnerabilities** at check time. Earlier npm and python-jose/ecdsa advisories were resolved. License metadata inventory covers 70 Python packages and 122 frontend runtime entries; React Leaflet declares Hippocratic-2.1 and certifi/tqdm include MPL terms. See DEPENDENCY_LICENSES.md.
- Docker: image built; initial nonroot migration failed because copied files retained root-only permissions, fixed with COPY ownership. Explicit migrations and readiness passed. Container login, ingestion, reopen, original hash, masked PDF download/hash and logout passed. Restart retained case/original/report with matching digests. A scratch restart-check field-name mistake was corrected before the passing check.
- Browser: shared cloud Chromium used the actual API. Synthetic benign and phishing uploads, all ten tabs, masking, case reopening, original/PDF verification and PDF downloads, alert acknowledgement/resolution, offline-unavailable IOC lookup, and mobile navigation were exercised. Accessibility findings were corrected and targeted checks rerun; automated audits and manual checks are not exhaustive accessibility certification.
- History and hygiene: scoped credential-pattern scan found no matches; original license retained; generated artifacts/secrets are excluded from Git. README/local-document links and whitespace were checked.

## External decisions needed for unconditional acceptance

1. Establish dataset/sample ownership and permitted use; obtain representative labelled groups and a sufficiently large independent evaluation set before production model claims.
2. Validate live provider accounts, quotas and disclosure policy in the intended deployment. Mock results are not live validation.
3. Confirm hosting plan, volume ownership/durability, TLS/CORS, backup/restore and retention/legal-hold policy. Review dependency license obligations for the intended use/distribution.

Detailed commands, tested input hashes and intermediate failures are retained in the task's workspace validation record. That task-local record is not committed because it contains sandbox-specific paths. The baseline audit describes the pre-implementation revision and should not be mistaken for the final state.

## Provider completion follow-up

VirusTotal existing-report and Shodan IP-host adapters are now implemented in the IOC workbench, superseding the earlier unimplemented status above. Thirteen provider tests passed, including credential absence, special-use exclusion, rate limits, malformed responses, URL identifiers and infrastructure-only Shodan semantics. Live accounts remain unverified. Provider dropdown and URL lookup are available in the frontend.


<!-- /coderabbit-ai-generated:v1 -->
## Storage and database verification follow-up

Added a read-only evidence reconciliation command; five storage/evidence tests passed. PostgreSQL 17 explicit migrations and 15 API/security/end-to-end checks passed. The initial PostgreSQL run exposed test fixtures retaining connections across event loops; disposing the engine at fixture teardown fixed isolation. This supersedes the earlier PostgreSQL-unverified statement. Remote hosting recovery and retention policy remain open.


<!-- /coderabbit-ai-generated:v1 -->
## ARC and license follow-up

Independent ARC verification now handles signed chains, tampered bodies and bounded chain work when DNS verification is enabled. It does not establish trust in sealing operators. This supersedes the earlier ARC-deferred statement. All 124 backend tests pass; pip-audit reports no known vulnerabilities. Live DNS remains unverified. Map wrappers react-leaflet and @react-leaflet/core were removed; Leaflet rendering and marker interaction passed in the shared cloud preview.


<!-- /coderabbit-ai-generated:v1 -->
## Candidate model safeguards

Training writes to a separate ignored candidate directory and rejects overwriting the deployed model, including symlink aliases. Saving a candidate preserves the active model cache. Twenty-two targeted training, ML and scoring tests passed, and a demonstration training run produced an explicitly uncalibrated candidate without modifying the bundled model. The seven-sample holdout remains inadequate for production claims; data ownership, a representative corpus and risk calibration require owner input. Final frontend privacy/render checks and production build pass; the IOC workbench has one provider selector.


<!-- /coderabbit-ai-generated:v1 -->