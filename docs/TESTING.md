<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:0eca0fca5af36e655e40b4eb2389385c0ecea070b4e4b8006676871900eae168 -->

# Testing and verification

Run from the repository root after installing the declared dependencies. Backend tests use synthetic fixtures and mock external providers; never point test commands at a production database or storage directories.

```sh
DATABASE_URL=sqlite+aiosqlite:////tmp/mailspectra-tests.db INTELLIGENCE_MODE=offline DEBUG=false REPORTS_DIR=/tmp/mailspectra-test-reports UPLOAD_DIR=/tmp/mailspectra-test-uploads python -m pytest -q --tb=short
npm --prefix frontend test
npm --prefix frontend run build
python -m scripts.generate_api_types
```

For PowerShell, set `$env:DATABASE_URL='sqlite+aiosqlite:///./test-only.db'` and separate temporary REPORTS_DIR/UPLOAD_DIR values before `python -m pytest -q`. Use an empty disposable test database. Do not reuse operator evidence directories.

Coverage includes password/session/role checks, login throttling, byte limits, parsing and duplicate headers, forged claims, signed/tampered DKIM fixtures, special IP ranges, migration preservation, original-byte tampering, canonical scoring, provider contracts/cache, graph provenance, case persistence, report hash/manifest, alert update and audit. The bundled MAILSPECTRA demo emails are also checked for RFC/MIME parse defects, reserved `.test` domains, RFC 5737-only IP literals, and plain-text-only attachment content. Frontend tests render six contract checks and verify privacy masking without altering source evidence. Browser testing complements these targeted tests; it is not exhaustive WCAG or cross-browser certification.

Two parameterized API workflows exercise synthetic benign and phishing messages from ingestion through reopen, original verification, masked PDF download and recomputed digest, manifest, alert acknowledgement and audit. External intelligence mocks cannot establish real account credentials/quota/terms or authoritative historical DNS. ML evaluation is reproducible but the tiny inherited dataset cannot establish operational accuracy.

Final software test counts and manual browser/Docker outcomes are recorded in PHASE_STATUS.md. Dependency review used `npm audit --audit-level=moderate` and `pip-audit -r requirements.txt`; the audit tool is not an application dependency. No known advisories remained at the time of the checks after Vite/React Router updates and replacement of python-jose/ecdsa with PyJWT. Re-audit during each release; ranges and upstream advisories can change.


<!-- /coderabbit-ai-generated:v1 -->