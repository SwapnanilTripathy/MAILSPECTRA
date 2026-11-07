<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:b0d2a6ddb98c73615a211f5202a77764bc65ddc5da88720375ed69c308522732 -->

# Deployment and operations

## Local and production settings

Use Python 3.11 and Node 24. The README contains POSIX and PowerShell setup. Copy `.env.example`, install requirements, run `python -m alembic upgrade head`, then `python -m backend.app.manage_users YOUR_USERNAME --role admin`. There are no shared/default credentials. The bootstrap command prompts without echo and refuses to overwrite an existing account.

Production requires `APP_ENV=production`, `DEBUG=false`, a random `SECRET_KEY` (at least 32 characters), explicit `CORS_ORIGINS`, durable `DATABASE_URL`, `UPLOAD_DIR` and `REPORTS_DIR`. Generate a key with `python -c "import secrets; print(secrets.token_urlsafe(48))"` in a private terminal and put it in your secret store. Do not share terminal output or commit it. Key rotation invalidates existing sessions. TLS terminates at the trusted hosting proxy; restrict access to the backend port. Add proxy request/concurrency/rate limits and a host memory/CPU budget.

## Docker

The image builds the SPA with Node 24 and serves it through Python 3.11 as UID 10001. Storage must be writable by that UID. From the repository root, set SECRET_KEY in your private environment or `.env`, then:

```sh
docker compose build
docker compose run --rm mailspectra python -m alembic upgrade head
docker compose run --rm mailspectra python -m backend.app.manage_users YOUR_USERNAME --role admin
docker compose up -d
curl --fail http://localhost:8000/api/v1/ready
```

Open `http://localhost:8000`. The named volume contains the SQLite database, original files and reports. Never use `docker compose down -v` when preserving evidence. A fresh volume requires migration before application startup. Existing schema upgrades must be backed up first. Downgrades are intentionally not a data-recovery procedure; restore a matched backup and image instead.

`/health` is process liveness. `/ready` checks database access, schema revision 0002 and writable artifact/report directories; a failure returns 503. The image healthcheck uses readiness. API requests have request IDs and bounded logging. Provider availability and model quality are separate from process readiness.

## Render / hosting

`render.yaml` declares one Docker web service, an evidence disk, offline intelligence, disabled debug, generated secret and a manually specified CORS origin. Deployment explicitly migrates before starting. Automatic deployment is disabled. Review billing/plan, disk ownership (UID 10001), disk durability, backup and the public HTTPS origin with the hosting operator before creating the service. No external cloud deployment was performed in this task. SQLite requires a single writer service on its durable disk; do not scale instances against separate local databases. PostgreSQL configuration is accepted but has not been integration-tested in this sandbox.

## Backup and restore

Quiesce ingestion, alert updates and report generation, then stop the application. Back up the entire persistent storage directory/volume (database plus originals, PDFs and manifests) as one versioned set. Preserve permissions and record the image/commit, migration revision and a checksum inventory. Encrypt off-site copies and restrict access. Provider keys/signing secrets belong in a separate protected secret-store backup, never in exported reports.

For local SQLite, copy the stopped database together with the upload/report directories. For Compose, use the operator's approved volume snapshot/backup tool against the `mailspectra_storage` volume while the service is stopped. Restore into an isolated replacement volume with UID 10001 ownership, start the matching application revision, check readiness, log in, reopen representative cases and recompute original/PDF digests before changing traffic. Test this restore periodically; this task verified container restart persistence, not disaster recovery on your hosting provider.

## Retention and recovery

Retention values shown in settings are policy metadata; **there is no automatic deletion job**. Operators must apply an approved retention/legal-hold policy to coordinated database records, originals, report versions and backups. Do not delete only database rows or only files. Old generated report versions can remain as historical files; include them in reconciliation and retention. On interrupted ingestion/report creation, reconcile referenced storage paths against database records and investigate orphan files before deletion. Audit records are application records, not an immutable external ledger.


<!-- /coderabbit-ai-generated:v1 -->