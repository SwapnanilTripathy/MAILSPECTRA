<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:70ffa6cc3d2877fe054bce8f6a204c4c17a278070ff1c4e000280a82708abf2a -->

<!-- coderabbit-ai-generated-section:v1:c7cb7ae90d968c009d55c8eee41a15ccf6ca43a961ef501cd78e88c6db7727c8 -->

<!-- coderabbit-ai-generated-section:v1:71edf5d73d0f176b988297450657df215860b1584f6fdb3e321eda266c90d50a -->

<!-- coderabbit-ai-generated-section:v1:344fef811069e466b40c3bb96238bd04697aa4f81ba432c02bb185da6584cb63 -->

<!-- coderabbit-ai-generated-section:v1:31725439d3863ea5f7c6ff2446e16844e0fbca6dacc2811994f4975f828af768 -->

# MAILSPECTRA

Email evidence analysis and investigation workspace derived from **DEEPTRACE / SIH26106**, originally developed by **sidharth63 / Team DEEP thinkers**. Original MIT copyright and license are retained in [LICENSE](LICENSE).

## Status and capabilities

Implemented: authenticated admin/analyst/viewer accounts; RFC 5322 `.eml` and pasted MIME ingestion; original-byte preservation and SHA-256 verification; duplicate headers, MIME, attachments and defanged indicators; reported versus verified authentication; persisted cases, alerts, graph evidence and campaign matches; backend IOC lookup; masked PDF export, manifests and audit records.

Experimental: the inherited 21-message demonstration model, uncalibrated probabilities, heuristic risk weights, infrastructure correlation and best-effort PII masking. The model is **not validated for operational detection**. Geolocation describes infrastructure, not a person's location. Authentication headers and relay claims in saved email can be forged. Read [the model card](docs/ML_MODEL_CARD.md) and [phase status](docs/PHASE_STATUS.md).

Unsupported/planned: Outlook `.msg`, attachment execution, URL retrieval, tenant isolation, SSO/MFA, guaranteed anonymization and an automatic legal-hold/retention engine. VirusTotal and Shodan provide optional existing-report lookups in the IOC workbench; live accounts require separate validation.

## Stack and architecture

Python 3.11, FastAPI, SQLAlchemy/Alembic, SQLite, scikit-learn 1.7.2, NetworkX, ReportLab; React 18, Vite 7, Node 24, Tailwind and Recharts. PostgreSQL 17 migrations and 15 API/security/end-to-end checks pass locally; production hosting remains unverified. [Architecture](docs/ARCHITECTURE.md) · [Data dictionary](docs/DATA_DICTIONARY.md) · [API](docs/API.md).

## Local setup

Run from the repository root with Python 3.11 and Node 24 installed:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python -m alembic upgrade head
python -m backend.app.manage_users YOUR_USERNAME --role admin
npm --prefix frontend ci
```

The account command prompts privately for a password. There are no default accounts or demo passwords. For Windows PowerShell, use `py -3.11 -m venv .venv`, `.\.venv\Scripts\Activate.ps1` and `Copy-Item .env.example .env`; remaining commands are the same.

Start `python backend/run.py` in one terminal and `npm --prefix frontend run dev -- --host 0.0.0.0` in another. Open `http://localhost:3000`. API readiness: `http://localhost:8000/api/v1/ready`; schema/docs: `http://localhost:8000/docs`. Offline intelligence is the default. Development generates a temporary signing key if unset, so sessions expire on API restart. Set a private random key for stable sessions; never commit `.env`.

## Verification and deployment

```sh
python -m pytest -q
npm --prefix frontend test
npm --prefix frontend run build
python -m scripts.generate_api_types
```

See [Testing](docs/TESTING.md) for isolated storage commands and verified results. [Deployment](docs/DEPLOYMENT.md) covers Docker, migration, account bootstrap, backups, restore and retention. Production requires explicit migrations, durable storage, a random signing key, explicit CORS origins, TLS and debug disabled. `docker compose up` alone does not initialize a new database: follow the documented migration step.

## Security, privacy and interpretation

Saved mail is untrusted evidence. The app never executes attachments or follows message URLs. Original artifacts remain private and unchanged by presentation masking. Live enrichment discloses queried indicators to external providers; map tiles and Google Fonts contact third parties. Offline fixtures are labelled synthetic and must not be cited as live intelligence. See [Security](docs/SECURITY.md), [Threat model](docs/THREAT_MODEL.md), [Providers](docs/INTELLIGENCE_PROVIDERS.md), [Forensics](docs/EMAIL_FORENSICS.md), [Evidence](docs/EVIDENCE_AND_CHAIN_OF_CUSTODY.md), [Risk scoring](docs/RISK_SCORING.md) and [Analyst workflow](docs/ANALYST_WORKFLOW.md).

Dataset authorship and redistribution rights remain unverified; the repository license alone does not establish rights to every inherited sample. Dependency inventory is recorded in `docs/dependency-licenses.json`; audit results are time-specific, not a security guarantee. See [Changelog](docs/CHANGELOG.md).


<!-- /coderabbit-ai-generated:v1 -->
## Final security hardening

See [Security and deployment hardening](docs/SECURITY_HARDENING.md) for reported versus verified authentication, rotating refresh cookies, revision0003, and explicit production PostgreSQL configuration. Docker/Compose now require DATABASE_URL; SQLite production additionally requires ALLOW_SQLITE_PRODUCTION=true. Earlier SQLite examples require this explicit operator choice.


<!-- /coderabbit-ai-generated:v1 -->