<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:5ffb05a6de50ce6222d01073bc37a6da49cf70e9755e30e8e614c8894b52e51a -->

# Threat model

Assets: original mail, attachments and indicators; user/session credentials; case snapshots and audit; reports/manifests; external provider keys. Actors include anonymous attackers, malicious email senders, authorized analysts, operators and external providers.

| Boundary/threat | Implemented control | Residual limitation |
| --- | --- | --- |
| Anonymous API access / forged tokens | Signed expiring tokens, database sessions, role checks | No SSO/MFA or tenant isolation |
| Password guessing | scrypt and persistent login attempt buckets | Concurrent/distributed admission still needs proxy throttling |
| Untrusted upload | Extension and content validation, byte cap including chunked requests, generated filenames | MIME/parser CPU and memory require host resource limits |
| Active HTML / malicious attachments | Text presentation, defanged indicators, no execution or URL fetch | Human copying/re-enabling indicators can expose risk |
| Forged authentication/Received | Reported/verified separation and cautious origin confidence | Saved mail lacks trusted SMTP envelope/acquisition boundary |
| External SSRF and disclosure | Provider allowlist, HTTPS, redirect/response/time bounds | DNS/provider queries intentionally disclose indicators in live mode |
| Evidence alteration | Original digest, verify endpoints, separate PDF digest | Hashes detect change; they do not authenticate acquisition or prevent operator tampering |
| Report markup / PII | Escaped ReportLab strings, optional recursive redaction, private storage | Best-effort masking is not guaranteed anonymization |
| Client token theft | Tab-scoped storage, no raw email HTML, restricted CORS | XSS in trusted application code can read sessionStorage |
| Log disclosure | Request IDs/status/duration without request bodies or provider indicators | Operators must protect application, proxy and platform logs |
| Storage failure / crash | DB transaction and normal file-failure cleanup; readiness probes | Backups and orphan reconciliation required; no cross-resource atomicity |

Original uploads and generated files are never mounted as public static content. Downloads require an authorized session. A digest match must not be called proof of sender authenticity or legal admissibility. Model results and correlation are investigative aids requiring analyst judgement. This is an implementation review, not an independent penetration test.


<!-- /coderabbit-ai-generated:v1 -->