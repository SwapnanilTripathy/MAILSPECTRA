# Authentication and API security

This page is a concise security overview. The detailed, current implementation notes and deployment requirements are maintained in [Security and deployment hardening](SECURITY_HARDENING.md). Keep that document authoritative when session or configuration behavior changes.

## Accounts and authorization

MAILSPECTRA is a single-organization application with three roles:

| Role | Access |
|---|---|
| `viewer` | Read investigations and permitted case information |
| `analyst` | Viewer access plus analysis, case updates, alert management, and report generation |
| `admin` | Analyst access plus protected system settings |

There is no public registration route, default administrator, shared demo password, SSO, MFA, or tenant isolation. Operators provision accounts after migrations using:

```bash
python -m backend.app.manage_users USERNAME --role admin
python -m backend.app.manage_users ANALYST_USERNAME --role analyst
python -m backend.app.manage_users VIEWER_USERNAME --role viewer
```

The command prompts for the password without echoing it. Do not pass passwords as command-line arguments or commit credentials.

Private API routes require authentication. Authorization is enforced at protected API boundaries; client-side route guards are not the security boundary.

## Passwords and sessions

- Passwords are stored using salted scrypt hashes.
- Access tokens are HS256-signed JWTs. The default access-token lifetime is **15 minutes** (configurable within the validated range).
- Tokens validate issuer, audience, token type, expiry, and a database-backed session reference.
- The database-backed session is checked during authenticated requests; logout revokes the session family.
- Login attempts are throttled using persisted login-attempt records. A production reverse proxy should also enforce request/concurrency limits.
- An opaque random refresh token is issued in an HttpOnly cookie. Raw refresh tokens are not returned in response JSON or stored in the database; only SHA-256 token digests are persisted.
- Successful refresh consumes the previous token and rotates to a new one. Reuse of a consumed token revokes its session family.
- The default refresh-session family lifetime is **7 days**. Rotation does not extend that absolute deadline.
- Production refresh cookies use Secure, HttpOnly, SameSite=Strict, host-only scope, and the `/api/v1/auth` path. Refresh requests require the configured CSRF header and validate Origin when supplied.

The current frontend stores short-lived access tokens in tab-scoped `sessionStorage`. This still requires strong XSS protection. The application does not render raw email HTML as active content.

## Production requirements

Production configuration must include:

- `APP_ENV=production` and `DEBUG=false`.
- A random `SECRET_KEY` of at least 32 characters.
- Explicit `CORS_ORIGINS` without a wildcard origin when credentials are enabled.
- An explicit durable `DATABASE_URL`; PostgreSQL is recommended.
- Durable, private upload and report storage with correct filesystem permissions.
- HTTPS at the trusted hosting proxy and restricted backend access.
- Database migrations applied before application startup.

SQLite production is allowed only through an explicit SQLite URL plus `ALLOW_SQLITE_PRODUCTION=true`, for an intentionally single-instance/single-writer deployment. Do not silently fall back to SQLite when PostgreSQL is unavailable.

## Email and indicator safety

Submitted email headers, bodies, relay claims, URLs, and attachment metadata are untrusted input. MAILSPECTRA does not execute attachments or automatically fetch message URLs. Supplied `Authentication-Results` values are reported claims, not independent SPF/DKIM/DMARC verification. See [Email forensics](EMAIL_FORENSICS.md) and [Security hardening](SECURITY_HARDENING.md) for mechanism-specific limitations.

Live intelligence lookups disclose the queried indicator to the configured external provider. Offline fixtures are labelled as fixtures; missing or unavailable information is not a clean verdict.

## Remaining limitations

The application is not an independent penetration-test certification. It does not provide SSO, MFA, multi-tenant isolation, guaranteed anonymization, or a distributed rate-limiting system. Operators remain responsible for proxy limits, secret management, TLS, backups, retention/legal-hold policy, and monitoring. The machine-learning model remains demonstration-only and uncalibrated.

See [Threat model](THREAT_MODEL.md), [Security hardening](SECURITY_HARDENING.md), and [Deployment](DEPLOYMENT.md) before exposing the service to real organizational email.
