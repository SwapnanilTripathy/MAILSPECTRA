<!-- coderabbit-ai-generated:v1 -->

# Security and deployment hardening

## Authentication trust

Responses now expose `reported_authentication` (UNVERIFIED header claims and original Authentication-Results values) separately from `verified_authentication` (independently established mechanism results). The existing `authentication` object remains for compatibility: its spf_result/dkim_result/dmarc_result fields are reported claims, not verification. Missing acquisition/verification yields UNAVAILABLE, never an inferred pass. Raw artifacts and headers are preserved unchanged. Existing frontend header views label claims as untrusted and display independent verification separately; reports retain these labels.

Reported passes never affect model features or reduce rule risk. Reported failures are attacker-controlled investigative signals: risk policy mailspectra-risk-3.1 assigns5 points per reported SPF/DKIM/DMARC fail or softfail, capped15. Verified failures have SPF10, DKIM10, DMARC15 weights, also capped15. The authentication bucket takes the maximum of these two totals, not their sum; there is no additive double counting. Indicators identify REPORTED versus VERIFIED explicitly, and normalized displayed contributions sum to the bucket. This heuristic is not authentication proof or a probability. Independent passes do not subtract from rule risk; they may populate independently verified model features.

DKIM/ARC require actual cryptographic verification and current DNS keys; a valid ARC chain does not establish trust in its sealer. Saved email lacks a trusted SMTP peer/envelope, so SPF remains unavailable. DMARC remains conservative when required mechanisms are unknown. DNS is disabled by default. The inherited model remains DEMONSTRATION_ONLY, UNCALIBRATED, production_ready=False. Authentication feature semantics are now stricter than the inherited training corpus, another reason operational model claims remain prohibited.

## Session lifecycle

Login returns a signed access JWT (default15 minutes, configurable1–30). It also sets an opaque random refresh cookie; raw refresh tokens never enter response JSON, browser storage or the database. The database retains SHA256 token digests and consumed flags, linked to the existing revocable session family. The family expires after7 days by default (configurable1–30); rotation does not extend that absolute deadline.

POST `/api/v1/auth/refresh` requires the HttpOnly refresh cookie, `X-Mailspectra-CSRF: 1`, and, when present, an Origin matching CORS_ORIGINS. Browser cross-origin custom-header requests require CORS preflight. Production cookies use Secure, HttpOnly, SameSite=Strict, host-only scope and path `/api/v1/auth`. Development HTTP omits Secure. Deploy the UI/API on the same site; cross-site refresh-cookie deployments are not supported by this Strict policy.

Successful refresh atomically consumes the stored digest, creates a replacement and returns a new short-lived access token. Reuse, including a concurrent second use, revokes the session family and all its access/refresh capability. PostgreSQL locks the family and a conditional token update also guards SQLite races. Current frontend requests share one refresh attempt per tab and retry only once; a simultaneous refresh from another tab or a lost rotation response can require sign-in again. This intentionally fails closed.

Logout authenticates with the bearer access token, revokes the family and clears the cookie. The frontend can refresh an expired access token before retrying logout. Missing/invalid/expired/revoked refresh tokens are rejected. Inactive users and unauthorized roles remain rejected. Existing roles are viewer, analyst and admin; student/faculty mappings require an owner decision. Access JWTs remain in sessionStorage (short-lived); protect the frontend against XSS. Signing-key rotation invalidates existing access JWTs; revoke database session families too when forcing all refresh sessions to end.

Keep consumed token hashes until their family expires so replay detection works. No automated session-history purge is introduced. Rate limiting remains persistent login throttling plus deployment proxy controls; distributed deployments need shared rate limits. Never log cookies, Authorization headers or private environment values.

## Database and deployment

Development defaults to SQLite. Production requires an explicit DATABASE_URL; PostgreSQL is recommended. Accepted PostgreSQL schemes `postgres://` and `postgresql://` normalize to `postgresql+asyncpg://`. A `sslmode` URL query parameter normalizes to asyncpg's `ssl` parameter; use the TLS mode required by your provider. Actual provider TLS is not validated here. Connection errors must not trigger fallback to SQLite; readiness returns503 when database access/schema/storage is unavailable.

SQLite production is permitted only with both an explicit SQLite DATABASE_URL and `ALLOW_SQLITE_PRODUCTION=true`, representing the operator's deliberate approval of a single-instance deployment. Do not use it for horizontally scaled services. Docker no longer supplies a hidden SQLite database URL. Compose requires DATABASE_URL. The Render blueprint requests a private DATABASE_URL instead of hardcoding SQLite.

For Render, an authorized operator must provision/select the intended PostgreSQL service, then configure its supplied connection URL as the web service's secret DATABASE_URL. Do not commit it. Use the same connection setting for explicit `python -m alembic upgrade head` before application startup. Revision0003 adds the refresh-token table without deleting existing records. Production startup/readiness require0003; create_all is not used. The blueprint runs the migration before starting one instance. Coordinate upgrades once per deployment and back up first; concurrent multi-instance migration orchestration is an operator responsibility.

Required production configuration: APP_ENV=production, DEBUG=false, random SECRET_KEY of at least32 characters, explicit DATABASE_URL, intended CORS_ORIGINS, durable UPLOAD_DIR/REPORTS_DIR with UID10001 ownership, and HTTPS at the trusted proxy. Settings validation suppresses input values in error messages. Configure ACCESS_TOKEN_MINUTES and REFRESH_TOKEN_DAYS only within their validated ranges. Authentication DNS and intelligence remain independently disabled/offline unless explicitly enabled.

No production database, paid service, TLS endpoint or live provider was configured in this task. Owner acceptance still includes secret storage, TLS, durable evidence volumes, production backup/replacement restore, retention/legal-hold policy, access provisioning and monitoring. The model's representative data and ownership requirements remain open.
