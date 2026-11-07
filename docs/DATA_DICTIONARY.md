<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:587ec028c88f021285eb08f6945a83cd6cfe6fdac4f186857c43e981c3bfa9c7 -->

# Data dictionary

Canonical response definitions: `backend/app/schemas/`; generated frontend declarations: `frontend/src/types/analysis.d.ts`. Runtime `/api/v1/openapi.json` is the API schema. Analysis `schema_version` is 1.1; legacy fields are retained where needed by existing consumers.

| Record/field | Meaning |
| --- | --- |
| `case_id` | Stable investigation identifier; not a filesystem path |
| `artifact.sha256` | Digest of exact original uploaded bytes |
| `artifact` / `evidence_manifest` | Original evidence identity, size, storage and acquisition metadata |
| `metadata` | Parsed sender, recipients, subject and message identifiers; untrusted message content |
| `authentication.reported` | Supplied claims, not independent verification |
| `authentication.verified` | Verification results plus source/limitations |
| `relay_chain` | Parsed Received observations; raw timestamps and trust limitations |
| `urls`, `ips`, `attachments` | Extracted observations, locations and hashes; no execution |
| `risk_assessment` | Final policy score (0–100), classification, severity and bounded breakdown |
| `ai_inference` | Model output, version/method and uncalibrated confidence; fallback confidence 0 |
| `infrastructure_intelligence` | Provider/source/status/time and optional facts; missing is not safe |
| `threat_graph.nodes[].node_type` | Canonical graph node kind |
| `threat_graph.edges[].evidence_refs` | Supporting observations for the relationship |
| `campaign_correlations[].shared_values` | Values supporting a possible related campaign |
| `full_analysis_json` | Persisted complete derived snapshot; never replaces original bytes |
| `report_sha256` | Digest of generated PDF, separate from original artifact digest |

Database tables include users, sessions, login attempts, cases, observations, timeline, audit, artifacts, alerts, campaigns and intelligence cache. Session revocation/expiry is checked per request. Alert states are OPEN, ACKNOWLEDGED and RESOLVED. Case states are OPEN, INVESTIGATING, RESOLVED and ARCHIVED. All users currently belong to one organization; roles control operations, not per-case ownership.

Provider statuses differ by typed adapter: FIXTURE, AVAILABLE, UNAVAILABLE, ERROR and RATE_LIMITED are distinct. `cache_hit` reports reuse; `looked_up_at`/`last_checked` report observation time, not a refreshed time on cache read. Unknown scores must not become zero-valued clean verdicts. Timestamps use UTC where recorded by the application; message timestamps are supplied evidence and can be missing/invalid.


<!-- /coderabbit-ai-generated:v1 -->