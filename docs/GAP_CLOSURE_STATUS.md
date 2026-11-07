<!-- coderabbit-ai-generated:v1 -->

# Gap closure status

The owner-provided gap-closure task was applied on `coderabbit/open-frontend-files/81a0d3ed`, starting at b3a7a045f8f60a5457c7b5723dccbc8857b41c31. Main was not modified.

## Implementation

- Alerts use canonical risk scores/classification and shared severity thresholds; LOW/INFORMATIONAL return no alert and persist no alert. Existing tests that expected informational alerts were corrected to enforce the new explicit contract.
- Parser version is centralized. Observations include original artifact references, header occurrence indexes, real MIME part indexes, snapshot pointers and explicit unavailable character offsets. Authentication verification is scoped to its mechanism; provider/fixture provenance is separate. Manifests are PRESENT_UNVERIFIED because no independent manifest digest is stored. Original and PDF digests are separate checks.
- Training verifies available dataset manifests, unions duplicate-text and supplied group/campaign/thread/sender IDs, reports support/split sizes, remains DEMONSTRATION_ONLY and cannot promote candidates. Model scores and hybrid risk remain uncalibrated. Dataset rights and representative evaluation remain unresolved.
- Attachment hashes persist as normalized observables; matching hashes contribute 0.45 to the existing bounded heuristic, equivalent to identical URL payload reuse. Temporal context adds no score. The configured window and elapsed days are shown, with legacy timestamps explicitly unavailable.
- Entropy describes the exact trimmed input string. The unvalidated DGA threshold and red/green verdicts were removed. No safety verdict is produced.
- Providers reject unsafe inputs, distinguish unsupported combinations, preserve UNKNOWN on malformed responses, reject credentialed redirects, and separate cache entries by provider/configuration. AbuseIPDB missing statistics no longer imply a clean result.
- `.github/workflows/acceptance.yml` runs isolated Python3.11 backend tests/schema drift and Node24 frontend install/tests/build on pushes and pull requests to main and the task branch. Actions are pinned, permissions read-only, no live secrets or deployment.

## Verification

Full local suite reached 151 passing tests before final mechanism-provenance and PDF-tamper additions. Frontend privacy and seven render checks plus production build passed. PostgreSQL17 migrations and15 API/security/end-to-end tests passed. Clean SQLite migrations run in fixtures; the legacy-preservation test passed. GitHub Actions run42397615258 passed both jobs on b2a43a04b2bdb74eea904e46e9689f33f6219010. Final SHA checks and full results are supplied in the task's completion report; this earlier run is not evidence for later edits.

## Operator acceptance — all OWNER ACTION REQUIRED

- Supply permission-cleared dataset ownership, labels and representative groups before any production model claim.
- Configure unique random production secret in the hosting secret manager and confirm CORS origins and TLS.
- Confirm persistent database/storage ownership, backups, replacement restore, and artifact/report digest survival on the actual host.
- Assign retention/deletion and legal-hold policy owners; no automatic deletion is enabled.
- Approve provider disclosure policy, quota and terms; supply credentials securely. Live account checks remain OPERATOR VERIFICATION REQUIRED.
- Provision initial admin and roles safely; establish monitoring and incident-response contacts.

For live smoke tests, an authorized operator should use one known harmless public indicator per configured provider, make one existing-report request, record provider/time/status/structural validity with sensitive values omitted, and confirm timeout/quota rules. Do not submit raw messages or attachments. Set INTELLIGENCE_MODE=offline to disable external intelligence; authentication DNS has its own disabled-by-default flag. No live provider calls or external deployment were performed.

Render configuration review: single nonroot Docker instance, persistent /app/storage disk, explicit migration before startup, readiness path, offline default, generated secret and operator-set CORS. This is configuration review only, not verification of a deployed host. SQLite is single-instance; distributed rate limiting and immutable external audit storage remain outside the current deployment guarantee.
