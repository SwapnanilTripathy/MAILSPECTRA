# DEEPTRACE

> **AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**  
> **Smart India Hackathon 2026** | **Problem Statement: SIH26106**  
> **Team:** DEEP thinkers

---

## Strategic Roadmap & Phase Status

| Phase | Focus Area | Status | Key Capabilities |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Email Forensics Foundation** | ✅ **COMPLETE** | RFC 822 / MIME parser, header forensics (SPF/DKIM/DMARC/ARC), relay path reconstruction & delay tracking, observable extraction (IPs, URLs, attachment hashes), defanging (`hxxp`, `[.]`). |
| **Phase 2** | **AI Threat Intelligence** | ✅ **COMPLETE** | Supervised ML classification (7 threat classes), TF-IDF text representation, 34 engineered forensic security signals, transparent 0-100 hybrid risk engine, and local linear SHAP explainability. |
| **Phase 3** | **Forensic Intelligence + Threat Graph** | ✅ **COMPLETE** | IP Geolocation & ASN lookup, DNS resolution, RDAP domain registration metadata, chronological origin assessment, real NetworkX threat graph, cross-case campaign correlation, and attribution support. |
| **Phase 4** | **SOC Platform + Investigation + Deployment** | ✅ **COMPLETE** | SOC command dashboard, investigation workspace, alert triage queue, case management, SHA-256 evidence chain of custody, timeline, court-grade PDF forensic report export, Dockerization. |

---

## Complete End-to-End Architecture (Phases 1 — 3)

```
                       ┌───────────────────────────────┐
                       │        Raw .EML Artifact      │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   Phase 1 Forensic Parser     │
                       │ • MIME Structure & Hashes     │
                       │ • Header Forensics (SPF/DKIM) │
                       │ • Relay Hop Reconstruction    │
                       │ • Extracted URLs & IPs        │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   Phase 2 Feature Extraction  │
                       │ • TF-IDF (1-2 N-grams) Text   │
                       │ • 34 Structured Security Feats│
                       └───────┬───────────────┬───────┘
                               │               │
            ┌──────────────────┘               └──────────────────┐
            ▼                                                     ▼
┌─────────────────────────────────┐               ┌─────────────────────────────────┐
│     Phase 2 ML Predictor        │               │   Phase 2 Transparent Risk      │
│ • Multi-class LogisticRegression│               │ • ML Threat Prob (up to 40 pts) │
│ • 7 Threat Class Probabilities  │               │ • Multi-layer Rules (60 pts)    │
└─────────────────┬───────────────┘               └─────────────────┬───────────────┘
                  │                                                 │
                  ▼                                                 │
┌─────────────────────────────────┐                                 │
│    Phase 2 SHAP Explainer       │                                 │
│ • Linear SHAP Attributions      │                                 │
│ • Human-readable Drivers        │                                 │
└─────────────────┬───────────────┘                                 │
                  │                                                 │
                  └────────────────────────┬────────────────────────┘
                                           │
                                           ▼
                       ┌───────────────────────────────────────┐
                       │   Phase 3 Infrastructure Intel        │
                       │ • GeoIP & ASN Resolution              │
                       │ • Safe DNS (A, MX, NS, TXT)           │
                       │ • RDAP Domain Metadata & Privacy      │
                       │ • Threat Feed Blacklist Queries       │
                       │ • Chronological Origin Assessment     │
                       └───────────────┬───────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌─────────────────────────────────┐               ┌─────────────────────────────────┐
│   Phase 3 NetworkX Threat Graph │               │  Phase 3 Campaign Correlation   │
│ • Nodes: Email, Domain, IP, ASN │               │ • Historical Case Cross-Match   │
│ • Edges: Sent_From, Resolves_To │               │ • Dynamic Threat Cluster Entity │
│ • Connected Components & Density│               │ • Attribution Support Engine    │
└─────────────────┬───────────────┘               └─────────────────┬───────────────┘
                  │                                                 │
                  └────────────────────────┬────────────────────────┘
                                           │
                                           ▼
                       ┌────────────────────────────────────────┐
                       │     Unified Structured JSON API        │
                       │ • observed_evidence                    │
                       │ • ai_inference                         │
                       │ • risk_assessment                      │
                       │ • shap_explanation                     │
                       │ • infrastructure_intelligence          │
                       │ • origin_assessment                    │
                       │ • threat_graph (nodes, edges, metrics) │
                       │ • campaign_correlations                │
                       │ • active_campaign                      │
                       │ • attribution_support                  │
                       │ • limitations                          │
                       └────────────────────────────────────────┘
```

---

## Phase 3 Forensic Intelligence & Graph Capabilities

### 1. IP Geolocation & ASN Intelligence
- **Provider Abstraction:** Implements `BaseGeoIPProvider` with pluggable `OfflineGeoIPProvider` and `LiveIPInfoProvider`.
- **Classification:** Strictly separates RFC1918/loopback private IPs from public routable IPs, preventing false geographical attributions.
- **Attributes:** Country, region, city, lat/long, ISP, ASN, organization, hosting provider, and proxy/VPN exit node detection.

### 2. DNS & Domain Intelligence
- **Safe DNS Resolution:** Queries `A`, `AAAA`, `MX`, `NS`, and `TXT` records using asynchronous `dnspython` with strict timeouts. Never visits malicious URLs or executes code.
- **Lexical Signals:** Calculates Shannon entropy for DGA detection, IDN Punycode indicators (`xn--`), subdomain depth analysis, and Leetspeak brand lookalike / typosquatting detection (e.g. `micr0s0ft`).
- **RDAP Domain Metadata:** Fetches registrar, creation date, expiration date, nameservers, domain status, and privacy protection flags without fabricating missing fields.

### 3. Chronological Origin Assessment
- Evaluates the chronological MTA relay path (`Received:` chain) starting from Hop 1.
- Identifies the **earliest reliable observable source IP** and public exit gateway.
- Transparently reports the evidentiary basis, confidence score, and clear limitations.

### 4. Real NetworkX Threat Graph
- Constructs an authentic `networkx.MultiDiGraph` relating:
  - `EMAIL` $\to$ `SENDER` (`SENT_FROM`)
  - `SENDER` $\to$ `DOMAIN` (`ASSOCIATED_WITH`)
  - `EMAIL` $\to$ `URL` (`CONTAINS_URL`)
  - `URL` $\to$ `DOMAIN` / `IP` (`RESOLVES_TO`)
  - `EMAIL` $\to$ `IP` (`TRANSMITTED_VIA`)
  - `EMAIL` $\to$ `MAIL_SERVER` (`TRANSMITTED_VIA`)
  - `IP` $\to$ `ASN` (`HOSTED_ON_ASN`)
  - `IP` $\to$ `LOCATION` (`LOCATED_IN`)
  - `DOMAIN` $\to$ `IP` (`RESOLVES_TO`)
  - `DOMAIN` $\to$ `MAIL_SERVER` (`ASSOCIATED_WITH`)
- Exports graph metrics (connected components, density) and serializable JSON structure.

### 5. Cross-Case Campaign Correlation & Attribution Support
- Automatically cross-matches newly analyzed emails against historical cases in the SQLite database (`deeptrace.db`).
- Discovers shared infrastructure across IPs, domains, URL payloads, senders, and threat patterns.
- Dynamically clusters related cases into a `CampaignEntity` (e.g. `CAMPAIGN-8A19F230`).
- Provides **Attribution Support** assessing technical hypotheses:
  - `SPOOFED_IDENTITY`
  - `LIKELY_COMPROMISED_ACCOUNT`
  - `ANONYMIZED_INFRASTRUCTURE`
  - `SHARED_CAMPAIGN_INFRASTRUCTURE`
  - `DIRECT_MALICIOUS_INFRASTRUCTURE`
  - `LEGITIMATE_AUTHENTICATED_SENDER`
  - `INSUFFICIENT_EVIDENCE`

---

## Evidence Provenance & Privacy Principles

Every intelligence observable explicitly states its provenance source:
- `EMAIL_HEADER` — Directly extracted from authenticated email headers.
- `EMAIL_BODY` — Extracted from body content or HTML markup.
- `URL_EXTRACTION` — Derived from hyperlink static parsing.
- `DNS` — Resolved via standard domain name system queries.
- `RDAP` — Retrieved from official domain registration registries.
- `GEOIP` — Geolocated route telemetry.
- `THREAT_INTEL` — Aggregated reputation feeds.
- `GRAPH_CORRELATION` — Inferred from cross-case observable links.
- `AI_INFERENCE` — Machine learning probability and SHAP attribution.

**Privacy Guarantee:** Full email bodies are **never** uploaded to third-party APIs. Only minimum discrete indicators (IP, domain, URL hash) are queried.

---

## Configuration & Modes

DeepTrace supports both offline development/testing and live external threat intelligence:

```env
# .env Configuration
INTELLIGENCE_MODE=offline            # "offline" for self-contained tests, "live" for production APIs
DNS_TIMEOUT_SECONDS=3.0
HTTP_INTEL_TIMEOUT_SECONDS=5.0
CACHE_TTL_HOURS=24

# Optional Live API Keys
IPINFO_TOKEN=
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
```

---

## Project Structure

```
DEEPTRACE/
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI routers & endpoints
│   │   │   └── v1/
│   │   │       ├── endpoints/
│   │   │       │   ├── health.py
│   │   │       │   └── analyze.py
│   │   │       └── router.py
│   │   ├── core/            # Config and structured logging
│   │   │   ├── config.py
│   │   │   └── logging.py
│   │   ├── database/        # SQLAlchemy session & base models
│   │   │   ├── base.py
│   │   │   └── session.py
│   │   ├── graph/           # Phase 3 NetworkX Threat Graph & Campaigns
│   │   │   ├── __init__.py
│   │   │   ├── schemas.py
│   │   │   ├── graph_builder.py
│   │   │   └── campaign_correlator.py
│   │   ├── intelligence/    # Phase 3 Geolocation, DNS, RDAP, Reputation
│   │   │   ├── __init__.py
│   │   │   ├── schemas.py
│   │   │   ├── geoip.py
│   │   │   ├── ip_intelligence.py
│   │   │   ├── dns_intelligence.py
│   │   │   ├── domain_intelligence.py
│   │   │   ├── rdap.py
│   │   │   └── reputation.py
│   │   ├── ml/              # Phase 2 Machine Learning & SHAP modules
│   │   │   ├── __init__.py
│   │   │   ├── schemas.py
│   │   │   ├── feature_extractor.py
│   │   │   ├── model_loader.py
│   │   │   ├── predictor.py
│   │   │   ├── explainer.py
│   │   │   ├── risk_engine.py
│   │   │   ├── train_model.py
│   │   │   └── models/      # Serialized models & metrics JSON
│   │   ├── models/          # Database ORM entities (cases, observables, campaigns)
│   │   │   ├── __init__.py
│   │   │   └── entities.py
│   │   ├── schemas/         # Pydantic validation schemas
│   │   │   ├── email.py
│   │   │   └── analysis.py
│   │   ├── services/        # Coordinated pipeline & services
│   │   │   ├── email_parser.py
│   │   │   ├── infrastructure_service.py
│   │   │   ├── correlation_service.py
│   │   │   └── threat_pipeline.py
│   │   └── utils/           # Cryptographic hashing & network helpers
│   │       ├── crypto.py
│   │       └── network.py
│   └── run.py               # Application entrypoint
├── data/
│   ├── samples/             # Sample .eml artifacts for testing
│   └── training/            # Demonstration training dataset
├── tests/                   # Pytest test suites (45 automated tests)
├── requirements.txt         # Production & ML dependencies
└── pytest.ini               # Pytest configuration
```

---

## Getting Started

### 1. Environment Setup
```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Running the Backend Server
```powershell
python backend/run.py
```
- **Interactive OpenAPI Documentation:** `http://127.0.0.1:8000/docs`
- **Email Analysis API:** `POST http://127.0.0.1:8000/api/v1/analyze/email`

### 3. Running the Frontend SOC Dashboard
```powershell
cd frontend
npm install
npm run dev
```
- **Web Application:** `http://localhost:3000`
- **Demo Analyst Credentials:** `analyst` / `deeptrace2026`

### 4. Running via Docker Container
```bash
docker-compose up --build
```
- **Access Container:** `http://localhost:8000`

### 5. Running Automated Tests
```powershell
pytest tests -v
```
All 53 automated tests execute offline with zero external network dependencies.

