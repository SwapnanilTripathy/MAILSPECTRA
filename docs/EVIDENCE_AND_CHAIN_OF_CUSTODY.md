<!-- coderabbit-ai-generated:v1 -->

# Evidence and chain of custody

Original bytes are hashed before parsing and written once to a random artifact filename outside the frontend root. Files use mode 0600, new storage directories 0700. Snapshots contain schema/parser version, ingestion actor/time, original filename, size, digest, observation IDs and an evidence manifest. Original files are never replaced by masked views.

Ingestion deduplicates by original SHA-256. Re-upload returns the same persisted analysis; it is not a new scan with fresh intelligence. Case status/assignment changes are separate audited operations. Legacy cases retain their snapshots, and may lack original evidence. No original bytes can be reconstructed from a legacy snapshot.

Case, observables, artifact metadata, initial timeline, audit and alert are committed together. Failure rolls back database writes and removes that attempt's file. A process crash between filesystem creation and database commit can leave an unreferenced file: operators should reconcile storage against the artifacts table before applying retention. Database and filesystem are not a distributed transaction.

`GET /api/v1/cases/{id}/evidence/verify` recalculates the original file digest. This detects differences relative to the stored digest, not administrator tampering with both database and files. Audit logs are application records, not an externally anchored immutable ledger.

## Migrations and recovery

Back up database, uploads and reports together before migration. Run `python -m alembic upgrade head` from the repository root. Revision 0001 freezes the inherited schema and adopts existing tables; 0002 adds sessions, login throttling, artifacts and alerts. Existing rows are preserved. Development startup applies migrations; production startup checks the expected revision and refuses an outdated schema. Downgrades deliberately refuse destructive deletion: restore the coordinated backup and corresponding application version instead.

Review deployment file permissions and volume ownership. Automatic evidence deletion is disabled; retention is operator-managed pending an organizational retention policy. Do not distribute real emails or expose artifact directories through a web server.
