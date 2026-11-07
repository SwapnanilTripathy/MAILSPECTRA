<!-- coderabbit-ai-generated:v1 -->

# MAILSPECTRA baseline audit

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:078e6739060a184ee6d18fb589dc96bca634d285043d097ea17b779d4c829ebc -->

**Phase:** 0 — verified baseline

**Status:** PARTIAL — source and local checks are complete; full history/data provenance, live provider behavior, container deployment, and a complete end-to-end audit remain unverified.

**Observed:** 2026-11-07

**Audited revision:** `3e71caef552e8b2e3b1ba04a90f57c6aef6d5f82` on `coderabbit/open-frontend-files/81a0d3ed`.

<!-- /coderabbit-ai-generated:v1 -->

This is an audit of the current checkout, including the UI and workflow changes committed before the master specification was supplied. It is not a claim of production readiness. The earlier upstream baseline is `8f9b342ad652d5f683573b7d7b345f75539f5640`. The only configured remote is the MAILSPECTRA `origin`. The working tree was clean when this audit began. The MIT `LICENSE` retains the upstream copyright; the README retains upstream attribution.

## Inventory and architecture

The tracked tree contains 124 files: Python FastAPI backend, React/Vite frontend, tests, a small training dataset and three email samples, a checked-in model artifact, Docker/Compose/Render configuration, and placeholder storage directories. The repository has no migration framework in the tracked tree. `requirements.txt` uses version ranges; `frontend/package-lock.json` locks frontend dependencies. Frontend scripts provide `dev`, `build`, and `preview`, with a Node test added for presentation masking; there is no configured frontend lint or full UI test suite.

- Browser: `frontend/src/App.jsx` routes to pages; `api/client.js` sends Axios requests to `/api/v1`; `AuthContext.jsx` manages the client session. Investigation panels render the response.
- API: `backend/app/main.py` mounts `api/v1/router.py`. Analyze endpoints read uploaded bytes or raw text and invoke `ThreatAnalysisPipeline`.
- Pipeline: `email_parser.py` parses and hashes the artifact; feature extraction, prediction, risk scoring and explanation follow. Content analysis and alert evaluation occur before infrastructure enrichment, graph construction and correlation/persistence. The response is optionally masked after the pipeline.
- Persistence: SQLAlchemy models include users, cases, observables, timeline, audit, campaigns and intelligence cache. `correlation_service.py` now serializes the full analysis before presentation masking and writes case/observable records. Case detail loads the snapshot. `POST /cases` separately creates a case or returns `EXISTS` without updating it. Reports read persisted case data and write PDF metadata. Original `.eml` bytes are not stored by this flow.
- Deployment: Vite proxies to port 8000; `Dockerfile` builds frontend assets and runs FastAPI. Compose configures offline intelligence and volumes; Dockerfile and Render specify live mode. `create_all()` initializes tables. Docker/Render behavior was inspected, not deployed or built in this audit.

## Verified observations from the specification

Status labels describe this checkout: **open** means verified and unresolved; **partial** means a repair exists but the full requirement remains; **not reproduced** means the specific claim did not hold in the inspected call path; **unverified** means further evidence is needed.

### Authentication and security (§3.1)

- **Partial:** the frontend no longer creates a fallback demo token and logout survives a reload (`frontend/src/context/AuthContext.jsx`). Backend login still accepts arbitrary nonempty credentials, creates unsigned token strings, `/auth/me` is hardcoded, and logout has no revocation (`backend/app/api/v1/endpoints/auth.py`).
- **Open:** route registration and endpoint dependencies contain no authentication enforcement (`backend/app/api/v1/router.py` and endpoints). With a clean local offline database and no Authorization header, cases, campaigns, reports, alerts, system settings, dashboard stats and `/auth/me` returned HTTP 200. A synthetic arbitrary nonempty login returned HTTP 200. Role checks, signed sessions, expiry, rate limiting and production secret enforcement remain absent from this path.
- **Open:** `backend/app/core/config.py` has a static fallback `SECRET_KEY` and development defaults. `.env.example` is tracked and contains a nonempty example `SECRET_KEY`; no value is reproduced here. Rotate any actual deployed credential if exposure is confirmed.

### Model and scoring (§3.2–3.3)

- **Open:** the checked-in `backend/app/ml/models/threat_classifier.joblib` is 53,662 bytes, SHA-256 `9ffdb9dc58490ad148b9e38a09e06e60b31175945f989cc0c33b137c698617b2`. The checked-in evaluation file describes 21 demonstration examples, CV accuracy 0.5714, macro F1 0.5463, training accuracy 1.0 and explicitly says the sample is not statistically significant. This audit did not retrain or independently validate the model.
- **Open:** `train_model.py` fits TF-IDF and scaling before cross-validation, allowing preprocessing leakage. The bundled model reported a scikit-learn 1.7.2 training version when loaded under 1.9.1; local verification used 1.7.2. The broad dependency range does not pin artifact compatibility.
- **Open:** risk components have caps totaling more than 100 before clipping while the methodology describes a 40/60 split (`backend/app/ml/risk_engine.py`). Severity thresholds also differ across consumers.
- **Not reproduced as stated:** in the normal pipeline, `threat_pipeline.py` copies the final risk score into `threat_assessment` before `AlertService` reads it, so an unconditional score divergence is not established by the cited code. It maps the legitimate class to `BENIGN`, and alert thresholds and other consumers still warrant consistency tests.

### Forensics and intelligence (§3.4–3.5)

- **Open:** SPF/DKIM/DMARC/ARC results are extracted from supplied headers; this is reported evidence, not independent SPF/DKIM/DMARC verification (`email_parser.py`). A signature alone is marked unverified.
- **Open:** offline GeoIP and reputation fixtures exist. Live GeoIP checks the fixture map and can label a fixture as `GEOIP`/`SUCCESS`; nonmatching offline reputation returns `CLEAN`/`AVAILABLE` (`intelligence/geoip.py`, `intelligence/reputation.py`). Provider results and special-use IP handling need a consistent source/status contract. `utils/network.py` does not exclude `is_reserved` from its `is_public` expression.
- **Unverified:** live provider behavior, credentials, rate limits, data freshness and whether any deployed provider transmits sensitive indicators. This audit used offline mode and synthetic data only.

### Frontend/backend field mismatches (§3.6)

| Audit item | Current status and evidence |
|---|---|
| Graph `node.type` vs `node_type` | **Open:** `ThreatGraphView.jsx` uses `type`; `graph/schemas.py` emits `node_type`. |
| Graph counts and connected components | **Open:** UI reads nested `metrics`; backend exposes `total_nodes`, `total_edges`, `connected_components_count`, and `density` at top level. UI synthesizes fallbacks. |
| Relay `ip` and `hop_number` | **Open:** UI uses these names; `schemas/email.py` defines `from_ip` and `hop_index`. |
| DNS and lexical fields | **Open:** `DnsRdapView.jsx` reads `dns_records` and `lexical_analysis`; backend has `dns` and top-level lexical fields. |
| IOC arrays | **Partial:** `InvestigatePage.jsx` now maps backend `urls` and `ips` into IOC rows. Domain/hash normalization and a canonical shared contract remain. |
| Campaign correlations and attribution | **Open:** UI expects `.correlations` and `hypothesis`; backend returns a list and `assessment`. |
| Attachment size | **Open:** UI reads `filesize_bytes`; backend defines `size_bytes`. |

### Persistence and additional observations (§3.7–3.8)

- **Partial — case snapshot:** newly analyzed cases store the full structured snapshot before presentation masking and a regression test verifies selected fields. Existing partial records are not upgraded; `POST /cases` preserves existing data. Raw artifact storage, migration, provenance and durable audit guarantees remain open. Persistence exceptions are caught in the correlation service, so a successful analysis response does not itself prove a case was stored.
- **Open — alerts:** the alert feed uses a process-memory buffer (`services/alert_service.py`).
- **Partial — standalone intelligence:** the local entropy result is now labelled as lexical only and reputation is “Not checked” (`IntelligencePage.jsx`). A backend lookup workbench remains unimplemented.
- **Open — graph:** `ThreatGraphView.jsx` uses custom SVG despite the ReactFlow dependency. The graph builder attaches relay observations to the email; a fully evidenced sequential relay graph is not established.
- **Open — attachments and input formats:** attachment extraction records metadata/hashes; no malware execution or sandbox is established. UI/backend still accept or advertise `.msg`, but the parser is RFC/MIME based. The server checks a configurable upload byte limit; its extension check warns rather than rejecting unsupported formats. Full content validation is unverified.
- **Open — privacy:** presentation masking is now applied to a copied result, but regex-based masking is not a complete PII redaction guarantee. Inputs and other views/exports may still expose sensitive data. Newly stored snapshots contain unmasked analysis; define access controls and retention before real use.
- **Open — reports:** the report generator uses inherited branding and states integrity is verified when generating the report. The separate verify endpoint recalculates a PDF hash, but a PDF hash alone does not prove original artifact integrity.
- **Open — migrations and deployment:** database initialization uses `create_all()`; no migration framework was found. Docker uses live intelligence by default, Compose uses offline mode, and Render persistence was not verified. Container build and backup/restore were not exercised.

## Validation and environment

The following checks were completed immediately before audit revision `3e71cae`; the commit contains the same tested working-tree inputs. They are reused here, not rerun merely for this documentation change.

| Check | Exact command / context | Outcome |
|---|---|---|
| Backend suite | `DATABASE_URL=sqlite+aiosqlite:////tmp/mailspectra-review-final-tests.db INTELLIGENCE_MODE=offline DEBUG=false REPORTS_DIR=/tmp/mailspectra-review-final-reports UPLOAD_DIR=/tmp/mailspectra-review-final-uploads /home/vercel-sandbox/runtime/mailspectra-venv/bin/python -m pytest -q` from repo root | **71 passed**, exit 0, Python 3.11.18. Includes case snapshot/masking and filtered pagination tests. |
| Frontend | `npm run build && node --test tests/privacy.test.js && git diff --check` from `frontend/` | **Build passed**, one Node test passed, exit 0. Vite warned about a bundle over 500 kB. Node 24.21.0, npm 11.19.0. |
| Local UI/API smoke | Shared Chromium on Vite port 3000 with isolated SQLite API on port 8000 and offline intelligence | Login, sample upload, displayed masking/IOC counts, case save, report generation and logout/reload were exercised. Pagination and failure screens also used synthetic intercepted responses. This is not full end-to-end coverage. |
| Health | `curl -fsS http://localhost:8000/api/v1/health` | Healthy local API response, exit 0. |

Preparation used `npm ci` and `pip install -r requirements.txt`. Initial SQLAlchemy 2.1 startup lacked `greenlet`; the previous commit selects the SQLAlchemy asyncio extra. The local Python environment was adjusted to scikit-learn 1.7.2 to match the serialized model. npm reported seven audit findings during installation; no dependency audit remediation was performed. The frontend production build and backend tests do not validate deployment or live intelligence services.

## Secrets and data review

`.gitignore` excludes local `.env` files, databases, uploads, reports and dependency/build artifacts; `.env.example` and three `.eml` sample files are tracked intentionally. A limited current-tree pattern scan found no matching private-key, GitHub-token or AWS-access-key formats; it is not a comprehensive secret scan or a full-history scan. Source inspection separately confirms prototype credentials and a fallback secret. The sample filenames and test use indicate fixtures, but this audit cannot establish their provenance or prove that no real personal data exists in the repository or history. Review history with an approved secret scanner and verify dataset/sample provenance before distribution. Do not copy secret values into reports.

## Open decisions and Phase 1 proposal

1. Agree on account provisioning, roles, session storage/revocation and migration for existing API clients. The current README documents demo access; enforcing backend authorization changes the public API contract. Preserve existing records and define rollout and rollback.
2. First Phase 1 slice: define the auth policy and configuration, add negative tests for missing/invalid/expired tokens and role boundaries, then implement password verification, signed expiring sessions and protected API routes together. Include authenticated report downloads and a documented local bootstrap path; remove demo bypasses only as part of the agreed transition.
3. Decide evidence storage/retention and how to handle older partial case snapshots before production deployment. No production data, live provider credentials, container deployment, or external service was used in this audit.
