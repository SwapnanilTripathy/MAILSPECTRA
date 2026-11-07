<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:a0bebffda0d40824c40e9d28ed8acaf003d403cc84032604b4ec209b02d27796 -->

<!-- coderabbit-ai-generated-section:v1:2331e229ee36b62838db51fcf15412d901ff46974af79e822ed869dfbb5cad46 -->

<!-- coderabbit-ai-generated-section:v1:f8a15675abf4c45dfde6c1517edb7e7c7f07f638bfaa5651af2ca696c4d5e3c6 -->

<!-- coderabbit-ai-generated-section:v1:44f314dbad413ed05b85b316bfae912d619adc3e23f6825243d35cb7d372bae6 -->

<!-- coderabbit-ai-generated-section:v1:b0d2a6ddb98c73615a211f5202a77764bc65ddc5da88720375ed69c308522732 -->

# Deployment and operations

## Local and production settings

Use Python 3.11 and Node 24. The README contains POSIX and PowerShell setup. Copy `.env.example`, install requirements, run `python -m alembic upgrade head`, then `python -m backend.app.manage_users YOUR_USERNAME --role admin`. There are no shared/default credentials. The bootstrap command prompts without echo and refuses to overwrite an existing account.

Production requires `APP_ENV=production`, `DEBUG=false`, a random `SECRET_KEY` (at least 32 characters), explicit `CORS_ORIGINS`, durable `DATABASE_URL`, `UPLOAD_DIR` and `REPORTS_DIR`. Generate a key with `python -c "import secrets; print(secrets.token_urlsafe(48))"` in a private terminal and put it in your secret store. Do not share terminal output or commit it. Key rotation invalidates existing sessions. TLS terminates at the trusted hosting proxy; restrict access to the backend port. Add proxy request/concurrency/rate limits and a host memory/CPU budget.

## Docker

The image builds the SPA with Node 24 and serves it through Python 3.11 as UID 10001. Storage must be writable by that UID. From the repository root, configure SECRET_KEY, CORS_ORIGINS and DATABASE_URL in your private environment or `.env`. PostgreSQL is recommended: use your external PostgreSQL connection URL; no database is provisioned by Compose. For an explicitly approved SQLite single-instance deployment, set `DATABASE_URL=sqlite+aiosqlite:////app/storage/mailspectra.db` and `ALLOW_SQLITE_PRODUCTION=true`. Then:

```sh
docker compose build
docker compose run --rm mailspectra python -m alembic upgrade head
docker compose run --rm mailspectra python -m backend.app.manage_users YOUR_USERNAME --role admin
docker compose up -d
curl --fail http://localhost:8000/api/v1/ready
```

Open `http://localhost:8000`. In either database configuration, the named volume mounted at `/app/storage` contains original email artifacts in `uploads/` and generated PDFs/manifests in `reports/`. With the explicit SQLite URL above it also contains `mailspectra.db`; with external PostgreSQL, database records live on that PostgreSQL service and are not backed up by copying this volume. Never use `docker compose down -v` when preserving evidence. A fresh database requires migration before application startup; a replacement evidence volume must contain the files referenced by that database. Existing schema upgrades must be backed up first. Downgrades are intentionally not a data-recovery procedure; restore a matched backup and image instead.

`/health` is process liveness. `/ready` checks database access, schema revision 0003 and writable artifact/report directories; a failure returns 503. The image healthcheck uses readiness. API requests have request IDs and bounded logging. Provider availability and model quality are separate from process readiness.

## Render / hosting

`render.yaml` declares one Docker web service, an evidence disk, offline intelligence, disabled debug, generated secret and a manually specified CORS origin and private external DATABASE_URL. PostgreSQL is recommended; the blueprint does not provision it or silently select SQLite. Deployment explicitly migrates before starting. Automatic deployment is disabled. Review billing/plan, disk ownership (UID 10001), disk durability, backup and the public HTTPS origin with the hosting operator before creating the service. No external cloud deployment was performed in this task. SQLite requires a single writer service on its durable disk; do not scale instances against separate local databases. PostgreSQL 17 migrations and 15 API/security/end-to-end tests have passed in an isolated container. Hosting-specific backup, restore and availability still require validation.

## Backup and restore

Quiesce ingestion, alert updates and report generation, then stop the application. Back up the persistent evidence directory/volume (originals, PDFs and manifests) and the configured database as one coordinated versioned set. For the explicit SQLite path above, the database is inside that volume. For external PostgreSQL, use the database provider's approved consistent backup/export procedure in addition to the evidence-volume backup; the evidence volume alone cannot restore case/session/correlation records. Preserve permissions and record the image/commit, migration revision and a checksum inventory. Encrypt off-site copies and restrict access. Provider keys/signing secrets belong in a separate protected secret-store backup, never in exported reports.

For local SQLite, copy the stopped database together with the upload/report directories. For external PostgreSQL, restore the matched database backup into an isolated replacement database and set DATABASE_URL accordingly, together with the matching evidence volume. For Compose evidence files, use the operator's approved volume snapshot/backup tool against the `mailspectra_storage` volume while the service is stopped. Restore into an isolated replacement volume with UID 10001 ownership, start the matching application revision, check readiness, log in, reopen representative cases and recompute original/PDF digests before changing traffic. Test this restore periodically; this task verified container restart persistence and a local stopped-volume backup restored into a separate volume. The restored database, original evidence and PDF hashes matched, readiness passed, and the read-only evidence audit passed. Disaster recovery on your hosting provider remains unverified.

## Retention and recovery

Retention values shown in settings are policy metadata; **there is no automatic deletion job**. Operators must apply an approved retention/legal-hold policy to coordinated database records, originals, report versions and backups. Do not delete only database rows or only files. Old generated report versions can remain as historical files; include them in reconciliation and retention. On interrupted ingestion/report creation, reconcile referenced storage paths against database records and investigate orphan files before deletion. Audit records are application records, not an immutable external ledger.


<!-- /coderabbit-ai-generated:v1 -->
## Read-only evidence inspection

Run `python -m backend.app.evidence_audit` with the application database/storage configuration. It reports missing or changed originals/PDFs, unsafe paths, missing manifests and unreferenced files without modifying anything. Exit 0 means the inspected references match; exit 2 means review is needed. Stop writes for a stable inventory. Older report versions can be unreferenced intentionally. Never delete reported files automatically; retention and legal-hold policy must be established first.


<!-- /coderabbit-ai-generated:v1 -->
## Final security hardening

See [Security and deployment hardening](SECURITY_HARDENING.md) for reported versus verified authentication, rotating refresh cookies, revision0003, and explicit production PostgreSQL configuration. Docker/Compose now require DATABASE_URL; SQLite production additionally requires ALLOW_SQLITE_PRODUCTION=true. Earlier SQLite examples require this explicit operator choice.


<!-- /coderabbit-ai-generated:v1 -->