# 🛡️ DEEPTRACE

<div align="center">

![DEEPTRACE Banner](https://img.shields.io/badge/DEEPTRACE-SOC%20Threat%20Intelligence%20Platform-00f0ff?style=for-the-badge&logo=shield&logoColor=black)

**AI-Powered Email Threat Detection, Infrastructure Geolocation & Digital Forensics Intelligence Platform**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.4-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4+-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-Multi--Stage-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![Tests](https://img.shields.io/badge/Tests-69%2F69%20Passed-brightgreen?style=flat-square&logo=pytest&logoColor=white)](https://pytest.org)
[![Production](https://img.shields.io/badge/Deployment-Live%20on%20Render-46E3B7?style=flat-square&logo=render&logoColor=white)](https://sih-26106.onrender.com)

**Smart India Hackathon 2026** | **Problem Statement: SIH26106** | **Theme: Blockchain & Cybersecurity**

[🌐 Live Web Application](https://sih-26106.onrender.com/) • [📖 Interactive API Docs](https://sih-26106.onrender.com/docs) • [📊 ReDoc Specification](https://sih-26106.onrender.com/redoc)

</div>

---

## 🌟 Overview & Technical Motivation

Email remains the primary vector for initial access in cybersecurity intrusions—including phishing, business email compromise (BEC), brand spoofing, and credential harvesting. Security Operations Center (SOC) analysts and digital forensics investigators require rapid, explainable, and evidence-preserving tools to deconstruct suspicious emails.

**DEEPTRACE** is an enterprise-grade Email Forensic & Threat Intelligence Platform developed for **Smart India Hackathon 2026 (SIH26106)**. It provides end-to-end forensic parsing, deterministic NLP content analysis, explainable machine learning threat scoring (linear SHAP), chronological Mail Transfer Agent (MTA) relay path reconstruction, GeoIP geolocation, safe DNS/RDAP infrastructure intelligence, relational NetworkX threat graphs, cross-case campaign clustering, automated security alerting, and cryptographic SHA-256 evidence preservation.

---

## 📋 SIH26106 Requirements Traceability Matrix

| SIH26106 Requirement | DEEPTRACE Implementation Component | Verification Status |
| :--- | :--- | :--- |
| **Email Parsing & Header Forensics** | `EmailForensicParser` (`email_parser.py`) — RFC 822/MIME, SPF, DKIM, DMARC, ARC, raw header extraction | ✅ Complete & Verified |
| **Defensible Forensic Fallbacks** | Clear `availability_status` ("Not available in supplied evidence") when auth/received headers are absent | ✅ Complete & Verified |
| **NLP & Explainable Content Intelligence** | `ContentIntelligenceAnalyzer` (`content_analyzer.py`) — Urgency, credential harvesting, financial BEC, impersonation | ✅ Complete & Verified |
| **Threat Classification & Risk Scoring** | `ThreatPredictor` + `ThreatRiskEngine` (`predictor.py`, `risk_engine.py`) — 7 threat classes, 0–100 hybrid score | ✅ Complete & Verified |
| **Explainable AI (SHAP)** | `ThreatExplainer` (`explainer.py`) — Local linear SHAP feature attributions and plain-language summaries | ✅ Complete & Verified |
| **Origin IP & Relay Path Reconstruction** | Chronological MTA traversal (`ip_intelligence.py`), latency calculation, earliest reliable origin assessment | ✅ Complete & Verified |
| **GeoIP Cartography & ASN Intelligence** | `GeoIPService` (`geoip.py`) — Latitude/longitude, country, ASN, ISP, Leaflet map integration | ✅ Complete & Verified |
| **Safe DNS & RDAP Intelligence** | `DNSIntelligenceService`, `RDAPService` (`dns_intel.py`, `rdap.py`) — Non-intrusive DNS records & ICANN RDAP | ✅ Complete & Verified |
| **Threat Intelligence Adapter Architecture** | `ThreatIntelAdapter` (`reputation.py`) — Live AbuseIPDB API with non-blocking offline database fallback | ✅ Complete & Verified |
| **Relational Threat Graph** | `ThreatGraphBuilder` (`graph_builder.py`) — NetworkX MultiDiGraph rendered via ReactFlow | ✅ Complete & Verified |
| **Cross-Case Campaign Correlation** | `CorrelationPersistenceService` (`correlation_service.py`) — Shared IOC clustering (`CAMPAIGN-{hash}`) | ✅ Complete & Verified |
| **Automated Real-Time Security Alerting** | `AlertService` (`alert_service.py`) + `/api/v1/alerts` — Configurable score thresholds & action triggers | ✅ Complete & Verified |
| **Privacy & PII Presentation Masking** | `PrivacyService` (`privacy_service.py`) — Redacted presentation view with raw evidence preservation | ✅ Complete & Verified |
| **Evidence Preservation & Reports** | `ForensicReportGenerator` (`report_generator.py`) — SHA-256 hashed PDF forensic report export | ✅ Complete & Verified |
| **Automated Test Suite** | Pytest test suite with 69 unit, integration, and resiliency test cases (`tests/`) | ✅ 69/69 Tests Passing |

---

## 🏛️ System Architecture

```
                       ┌─────────────────────────────────────────┐
                       │          Raw .EML Artifact              │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   Stage 1: Forensic Email Extraction    │
                       │ • SHA-256 Artifact Cryptographic Hash   │
                       │ • Strict MIME Multipart & Body Parsing  │
                       │ • SPF, DKIM, DMARC & ARC Validation     │
                       │ • Chronological MTA Relay Reconstruction│
                       │ • Observable Extraction & Defanging     │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   Stage 2: Hybrid AI & Content Engine   │
                       │ • Deterministic NLP Content Signals     │
                       │ • TF-IDF Lexical Feature Extraction     │
                       │ • 34 Engineered Forensic Security Stats │
                       │ • Multi-Class Threat Classification     │
                       │ • Transparent 0-100 Hybrid Risk Engine  │
                       │ • Local Linear SHAP Attribution Scoring │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   Stage 3: Infrastructure Intelligence  │
                       │ • Real-time GeoIP Coordinates & ASN     │
                       │ • Safe Non-Intrusive DNS (A, MX, TXT)   │
                       │ • Official ICANN / RIR RDAP Registration│
                       │ • Threat Intel Adapter (Live + Offline) │
                       │ • Earliest Observed Sending Gateway     │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   Stage 4: Threat Graph & Alerting      │
                       │ • NetworkX MultiDiGraph Engine          │
                       │ • Automated Security Alert Generation   │
                       │ • Cross-Case Observable Correlation     │
                       │ • Dynamic Campaign Clustering           │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   Stage 5: SOC Command Center & Reports │
                       │ • React 18 + Tailwind Dark SOC UI       │
                       │ • Interactive Leaflet GeoIP Map         │
                       │ • Interactive ReactFlow Threat Graph    │
                       │ • Privacy Presentation View (PII Mask) │
                       │ • Evidence-Preserving PDF Reports       │
                       └─────────────────────────────────────────┘
```

---

## 🚀 Live Production Deployment

DEEPTRACE is continuously deployed and accessible online:

| Resource | Public Production URL | Description |
| :--- | :--- | :--- |
| **Full-Stack Application** | **[https://sih-26106.onrender.com](https://sih-26106.onrender.com/)** | Unified SOC Investigation Platform |
| **REST API Base** | `https://sih-26106.onrender.com/api/v1` | Production FastAPI Backend Endpoint |
| **Interactive Swagger UI** | `https://sih-26106.onrender.com/docs` | Live API testing & interactive documentation |
| **ReDoc API Spec** | `https://sih-26106.onrender.com/redoc` | OpenAPI 3.1.0 specifications |

### Prototype Analyst Credentials
| Parameter | Value | Role |
| :--- | :--- | :--- |
| **Username** | `analyst` | Lead Incident Investigator |
| **Password** | `deeptrace2026` | Full Investigation & PDF Export Access |
| *(Admin Alternative)* | `admin` / `admin` | Security Administrator |

---

## ⚡ Core Feature Deep Dive

### 1. 📧 RFC 822 / MIME Deep Forensics
* **Artifact Integrity:** Automatically calculates SHA-256, SHA-1, and MD5 evidence digests on raw uploaded `.eml` files before parsing.
* **Authentication Validation:** Parses SPF, DKIM signatures, DMARC policies, and ARC seals from headers. If authentication headers are missing, DEEPTRACE explicitly records `"Not available in supplied evidence"` rather than assuming validation failure.
* **MIME Parsing:** Recursively extracts nested body parts, HTML DOM elements, plain text, inline scripts, attachments, and headers.
* **Defanging & Safety:** Automatically defangs high-risk observables (`http` $\to$ `hxxp`, `.` $\to$ `[.]`) to protect analysts during triage.

### 2. 📝 Explainable NLP & Content Intelligence
* **Deterministic Signal Detection:** Employs regex patterns and lexical token analyzers to detect social engineering indicators across 8 distinct threat dimensions:
  - **Urgency Language:** Immediate action requests, countdown ultimatums, deadline pressure.
  - **Credential Harvesting:** Login redirection, password reset prompts, verify identity cues.
  - **Financial / BEC:** Wire transfer requests, invoice changes, bank account modifications.
  - **Impersonation Pretexts:** Executive communication patterns, board meeting authority pretexts.
  - **Account Suspension Warnings:** Account frozen, security alert, unauthorized access warnings.
  - **Suspicious Call-To-Action:** Generic click-here directives, unverified portal links.
  - **URL / Host Anomalies:** Raw IP hyperlinks, domain mismatch, link shortener services.
  - **Dangerous Attachments:** Executable or macro-enabled extensions (`.docm`, `.xlsm`, `.exe`, `.vbs`, `.iso`).

### 3. 🛰️ Chronological MTA Relay Transit & Origin Assessment
* **Hop Reconstruction:** Analyzes all `Received:` header blocks in reverse chronological sequence (Hop 1 = earliest observable gateway).
* **Transit Latency Tracking:** Measures hop-to-hop delay timestamps in seconds to detect relay throttling or abnormal transit anomalies.
* **Defensible Origin Basis:** Identifies the earliest observed sending infrastructure without overstating attribution as "the attacker IP." If Received headers are absent, DEEPTRACE clearly states: `"Relay path unavailable — no usable Received headers were present in the supplied artifact."`

### 4. 🧠 Hybrid AI Threat Scoring & Explainable AI (SHAP)
* **7 Threat Classes:** Categorizes email threats into `BENIGN`, `SPAM`, `PHISHING`, `SUSPICIOUS`, `SPOOFING`, `BEC`, and `MALWARE_DELIVERY`.
* **34 Engineered Security Signals:** Header mismatches, urgent keywords, suspicious attachments, authentication failures, DGA entropy, Punycode indicators, and IP-host links.
* **Transparent Risk Score (0–100):** Combines machine learning probability (up to 40 pts) with deterministic security rules (up to 60 pts).
* **SHAP Explainability:** Provides mathematically sound feature attributions showing exactly why the model made its decision.

### 5. 🗺️ Real-Time GeoIP Cartography & ASN Intelligence
* **Global Mapping:** Resolves real-world latitude, longitude, country, city, ISP, ASN, and organization for every public IP in the relay path.
* **Interactive Map:** Displays an interactive Leaflet map marking origin infrastructure and transit relay nodes.
* **Safe Dual-Mode:** Supports both live online lookups (`ip-api.com` / `ipinfo.io`) and zero-dependency offline fixtures for closed test environments.

### 6. 🔌 Threat Intelligence Adapter & Offline Mode
* **Pluggable Architecture:** Implements `BaseThreatIntelProvider`, `OfflineThreatIntelProvider`, and `LiveAbuseIPDBProvider` under a unified `ThreatIntelAdapter`.
* **Graceful Degradation:** If live external APIs are unconfigured, rate-limited, or unreachable, DEEPTRACE degrades gracefully to local offline intelligence without causing analysis failure.

### 7. 🚨 Real-Time Automated Security Alerting
* **Configurable Thresholds:** Evaluates risk scores against configurable thresholds (`ALERT_THRESHOLD_SCORE = 60.0`, `CRITICAL_ALERT_SCORE = 80.0`).
* **Trigger Extraction & Remediation:** Automatically generates structured `SecurityAlert` events with severity rating, trigger causes, and SOC remediation playbooks.
* **Alert Feed API:** Exposes `/api/v1/alerts` and `/api/v1/alerts/config` for SIEM and SOAR integrations.

### 8. 🛡️ Privacy & PII Presentation Masking
* **Masked Presentation View:** Analysts can toggle sensitive-field masking for presentation and demonstration views (redacting email addresses, IP host octets, and display names).
* **Evidence Integrity:** Redaction is applied strictly at the presentation layer without modifying or corrupting the underlying forensic artifact or its SHA-256 fingerprint.

### 9. 🕸️ Relational Threat Graph (NetworkX MultiDiGraph)
* **Graph Architecture:** Models complex infrastructure relationships across:
  - `EMAIL` $\to$ `SENDER` (`SENT_FROM`)
  - `SENDER` $\to$ `DOMAIN` (`ASSOCIATED_WITH`)
  - `EMAIL` $\to$ `URL` (`CONTAINS_URL`)
  - `URL` $\to$ `DOMAIN` / `IP` (`RESOLVES_TO`)
  - `EMAIL` $\to$ `IP` (`TRANSMITTED_VIA`)
  - `IP` $\to$ `ASN` (`HOSTED_ON_ASN`)
  - `IP` $\to$ `LOCATION` (`LOCATED_IN`)
* **Visual Graph Workspace:** Rendered interactively in the web UI using ReactFlow with zoom, pan, and node inspection.

### 10. 🔗 Cross-Case Campaign Correlation & Attribution
* **Automated Threat Clustering:** Queries historical cases in the persistent SQLite database to detect shared attack infrastructure (shared IPs, payload URLs, spoofed domains, or sender patterns).
* **Campaign Discovery:** Groups related attacks under unified Campaign IDs (e.g. `CAMPAIGN-8A19F230`).
* **Technical Attribution Hypotheses:** Evaluates evidence against structured threat hypotheses (`SPOOFED_IDENTITY`, `COMPROMISED_ACCOUNT`, `ANONYMIZED_INFRASTRUCTURE`, `SHARED_CAMPAIGN_INFRASTRUCTURE`).

### 11. 📄 Evidence-Preserving PDF Forensic Report Generation
* **ReportLab Engine:** Generates tamper-evident forensic PDF incident reports with one click.
* **Evidence Chain of Custody:** Includes SHA-256 evidence digests, analyst session stamps, full header breakdowns, risk breakdown charts, observable tables, and limitations disclaimers.

---

## 💻 Technology Stack

| Layer | Technologies Used | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | FastAPI, Starlette, Uvicorn, Pydantic v2 | High-performance asynchronous REST API |
| **Machine Learning** | Scikit-Learn, SHAP, NumPy, SciPy, Joblib | Threat classification & explainability |
| **Graph Intelligence** | NetworkX | Relational infrastructure threat graph modeling |
| **Forensics & Network** | dnspython, tldextract, beautifulsoup4, httpx | Safe DNS, MIME parsing, RDAP, GeoIP |
| **PDF Generation** | ReportLab | Evidence-preserving forensic incident reports |
| **Database** | SQLAlchemy 2.0 (Async), aiosqlite | Asynchronous SQLite / PostgreSQL persistence |
| **Frontend Framework** | React 18, Vite 5.4, React Router 6 | Lightning-fast SOC user interface |
| **Styling & Icons** | Vanilla CSS + TailwindCSS, Lucide-React | Dark SOC glassmorphism design system |
| **Visualization** | ReactFlow, Recharts, React-Leaflet | Graph topology, charts, and GeoIP cartography |
| **Container & Cloud** | Docker Multi-Stage, Render Cloud | Unified single-container production deployment |

---

## 🛠️ Local Development & Quick Start

### 1. Prerequisites
- Python 3.10 or 3.11
- Node.js 18+ and npm
- Git

### 2. Clone Repository
```bash
git clone https://github.com/sidharth63/SIH_26106.git
cd SIH_26106
```

### 3. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate    # Linux / macOS

# Install Python dependencies
pip install -r requirements.txt

# Start backend server
python backend/run.py
```
* Backend starts at `http://127.0.0.1:8000`
* Interactive API Documentation: `http://127.0.0.1:8000/docs`

### 4. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
* Frontend starts at `http://localhost:3000`

---

## 🧪 Automated Test Suite

DEEPTRACE includes a comprehensive test suite covering forensic parsing, content analysis, alert thresholds, privacy masking, ML prediction, graph construction, database operations, and API endpoints:

```bash
python -m pytest
```

```text
============================= test session starts =============================
platform win32 -- Python 3.10.0, pytest-9.1.1, pluggy-1.6.0
rootdir: DEEPTRACE
collected 69 items

tests\test_alert_and_privacy.py ......                                   [  8%]
tests\test_api.py ........                                               [ 20%]
tests\test_content_analyzer.py ......                                    [ 28%]
tests\test_email_parser.py ...........                                   [ 44%]
tests\test_intelligence_and_graph.py ..................                  [ 71%]
tests\test_ml_pipeline.py ............                                   [ 88%]
tests\test_soc_platform.py ........                                      [100%]

============================= 69 passed in 55.17s =============================
```

---

## ⚠️ Current Prototype Limitations & Scope

In accordance with responsible engineering practices, the current prototype scope and limitations are transparently documented:

1. **Static Analysis Only:** DEEPTRACE performs static forensic inspection of email artifacts and safe, non-intrusive DNS/RDAP queries. It does not execute dynamic sandboxing or detonating malware binaries.
2. **Header Reliance:** Relay path reconstruction relies on the presence of RFC 822 `Received:` headers. When headers are absent or stripped, DEEPTRACE identifies this condition explicitly rather than estimating or fabricating hops.
3. **Attribution Boundaries:** DEEPTRACE identifies the earliest observed public sending infrastructure in the relay chain. It does not claim definitive individual attribution or legal liability without corroborating corroborative law enforcement logs.
4. **Third-Party API Rate Limits:** Live reputation lookups (e.g. AbuseIPDB, VirusTotal) depend on external API quotas. When unconfigured or exceeded, DEEPTRACE gracefully falls back to deterministic offline intelligence.

---

## 👥 Smart India Hackathon 2026

* **Problem Statement:** SIH26106 — Email Threat Intelligence, Forensic Analysis & Relational Graph Platform
* **Team Name:** DEEP thinkers
* **Lead Developer / Author:** Rompicharla Siddharth ([@sidharth63](https://github.com/sidharth63))
* **Repository:** [https://github.com/sidharth63/SIH_26106](https://github.com/sidharth63/SIH_26106)
* **Production Deployment:** [https://sih-26106.onrender.com](https://sih-26106.onrender.com/)

---

<div align="center">

*Built with precision and technical rigor by Team DEEP thinkers.*

</div>
