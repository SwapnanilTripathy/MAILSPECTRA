<!-- coderabbit-ai-generated:v1 -->

# Authentication and API security

MAILSPECTRA uses single-organization accounts with `admin`, `analyst`, and `viewer` roles. Viewers read investigations; analysts also analyze, update cases and generate reports. Only administrators read system settings. Health and login are public. All other API routes require bearer authentication, including report download.

Passwords use salted scrypt (N=32768, r=8, p=1). Access tokens are HS256 signed, expire after 30 minutes, validate issuer/audience/type, and reference database sessions checked on every request. Logout revokes the session. Disabling a user takes effect immediately. No refresh tokens or built-in accounts exist. Legacy unsigned tokens and legacy password formats are rejected. The account table and case records are preserved.

Run database initialization/migrations before `python -m backend.app.manage_users YOUR_USERNAME --role admin`. Passwords are entered through a hidden prompt; never pass passwords on the command line. Run again with a new username to provision analysts/viewers. Existing accounts with unsupported password hashes require operator-controlled credential reprovisioning; there is no public registration/reset route.

Set a random `SECRET_KEY` with at least 32 characters for stable sessions. Production fails on a missing/weak key, debug mode or wildcard CORS. Development generates a temporary key if omitted, invalidating sessions after restart. Use HTTPS and an explicit origin list in production.

Browser access tokens live in sessionStorage for the browser tab, not persistent localStorage. This still requires protection from XSS: no raw email HTML is rendered. Download buttons fetch PDF blobs with the bearer header. Legacy localStorage tokens are cleared. Login attempts are counted in the database by direct client IP over a five-minute window; configure a reverse proxy rate limit as well, especially for concurrent requests/multiple workers and shared proxy IPs. Forwarded headers are not trusted by this application.

API compatibility: anonymous private API access and demo passwords have been deliberately removed under the owner's full-specification authorization. Existing API clients must authenticate. Rollback requires restoring the application and database backup together; do not deploy the prototype authentication publicly.

Validation: 75 backend tests passed, including absent/invalid/expired/revoked tokens and viewer/analyst permissions. Frontend production build and privacy test passed. Browser session workflow will be checked again during the final integration gate.
