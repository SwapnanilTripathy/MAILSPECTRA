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
[![Tests](https://img.shields.io/badge/Tests-53%2F53%20Passed-brightgreen?style=flat-square&logo=pytest&logoColor=white)](https://pytest.org)
[![Production](https://img.shields.io/badge/Deployment-Live%20on%20Render-46E3B7?style=flat-square&logo=render&logoColor=white)](https://sih-26106.onrender.com)

**Smart India Hackathon 2026** | **Problem Statement: SIH26106** | **Team:** DEEP thinkers

[🌐 Live Web Application](https://sih-26106.onrender.com/) • [📖 Interactive API Docs](https://sih-26106.onrender.com/docs) • [📊 ReDoc Specification](https://sih-26106.onrender.com/redoc)

</div>

---

## 🌟 The Genesis: The Birth of DEEPTRACE

In modern cybersecurity operations, email remains the #1 initial access vector for critical infrastructure breaches, ransomware campaigns, business email compromise (BEC), and state-sponsored espionage. Yet, Security Operations Center (SOC) analysts face an overwhelming dilemma:

1. **Legacy Filters are Black Boxes:** Traditional spam filters produce binary pass/fail verdicts without explaining *why* an email is malicious.
2. **Attribution is Fragmented:** Analysts waste critical hours manually pivoting across Whois, DNS lookup tools, GeoIP databases, header analyzers, and sandboxes.
3. **Campaigns Go Unnoticed:** Attackers reuse domains, IP subnets, and payload delivery tactics across multiple targets, but siloed investigations fail to correlate isolated incidents into broader coordinated campaigns.

### 💡 The Vision
Born out of **Smart India Hackathon 2026 (SIH26106)**, **DEEPTRACE** was created by **Team DEEP thinkers** as an end-to-end, enterprise-grade Digital Forensics and Incident Response (DFIR) platform. 

DEEPTRACE merges **deep header forensics**, **explainable machine learning (SHAP)**, **chronological MTA relay path reconstruction**, **real-time GeoIP cartography**, **safe DNS/RDAP querying**, and **interactive NetworkX graph theory** into a unified, court-admissible SOC investigation command center.

---

## 🚀 Live Production Deployment

DEEPTRACE is fully deployed and accessible 24/7 online:

| Resource | Public Production URL | Description |
| :--- | :--- | :--- |
| **Full-Stack Application** | **[https://sih-26106.onrender.com](https://sih-26106.onrender.com/)** | Unified SOC Investigation Platform |
| **REST API Base** | `https://sih-26106.onrender.com/api/v1` | Production FastAPI Backend Endpoint |
| **Interactive Swagger UI** | `https://sih-26106.onrender.com/docs` | Live API testing & interactive documentation |
| **ReDoc API Spec** | `https://sih-26106.onrender.com/redoc` | OpenAPI 3.1.0 specifications |

### 🔑 Prototype Analyst Credentials
| Parameter | Value | Role |
| :--- | :--- | :--- |
| **Username** | `analyst` | Lead Incident Investigator |
| **Password** | `deeptrace2026` | Full Investigation & PDF Export Access |
| *(Admin Alternative)* | `admin` / `admin` | Security Administrator |

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
                       │   Stage 2: Hybrid AI Threat Engine      │
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
                       │ • Lexical Heuristics (Entropy, Typos)   │
                       │ • Chronological Origin IP Assessment    │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   Stage 4: Relational Graph & Campaigns │
                       │ • NetworkX MultiDiGraph Engine          │
                       │ • Cross-Case Observable Correlation     │
                       │ • Dynamic Campaign Clustering (Louvain) │
                       │ • Technical Attribution Hypotheses      │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   Stage 5: SOC Command Center & Reports │
                       │ • React 18 + Tailwind Dark SOC UI       │
                       │ • Live Leaflet GeoIP Cartography Map    │
                       │ • Interactive ReactFlow Threat Graph    │
                       │ • Court-Grade PDF Report Generation     │
                       │ • Cryptographic Chain of Custody Audit  │
                       └─────────────────────────────────────────┘
```

---

## ⚡ Key Capabilities & Feature Breakdown

### 1. 📧 RFC 822 / MIME Deep Forensics
* **Artifact Integrity:** Automatically calculates SHA-256 evidence digests on raw uploaded `.eml` files before parsing.
* **Authentication Validation:** Parses SPF, DKIM signatures, DMARC policies, and ARC seals from headers.
* **MIME Parsing:** Recursively extracts nested body parts, HTML tags, inline scripts, attachments, and headers.
* **Defanging & Safety:** Automatically defangs high-risk observables (`http` $\to$ `hxxp`, `.` $\to$ `[.]`) to protect analysts during triage.

### 2. 🛰️ Chronological MTA Relay Transit & Origin Assessment
* **Hop Reconstruction:** Analyzes all `Received:` header blocks in reverse chronological sequence (Hop 1 = origin client/gateway).
* **Transit Latency Tracking:** Measures hop-to-hop delay timestamps in seconds to detect relay throttling or abnormal transit anomalies.
* **Earliest Observable Origin:** Discovers the earliest reliable public routable IP while filtering out RFC1918 private/loopback address space.

### 3. 🧠 Hybrid AI Threat Scoring & Explainable AI (SHAP)
* **7 Threat Classes:** Categorizes email threats into `BENIGN`, `SPAM`, `PHISHING`, `SUSPICIOUS`, `SPOOFING`, `BEC`, and `MALWARE_DELIVERY`.
* **34 Engineered Security Signals:** Header mismatches, urgent keywords, suspicious attachments, authentication failures, DGA entropy, Punycode indicators, and IP-host links.
* **Transparent Risk Score (0–100):** Combines machine learning probability (up to 40 pts) with deterministic security rules (up to 60 pts).
* **SHAP Explainability:** Provides mathematically sound feature attributions showing exactly why the model made its decision.

### 4. 🗺️ Real-Time GeoIP Cartography & ASN Intelligence
* **Global Mapping:** Resolves real-world latitude, longitude, country, city, ISP, ASN, and organization for every public IP in the relay path.
* **Interactive Map:** Displays an interactive Leaflet map marking origin infrastructure and transit relay nodes.
* **Safe Dual-Mode:** Supports both live online lookups (`ip-api.com` / `ipinfo.io`) and zero-dependency offline fixtures for closed test environments.

### 5. 🔍 Safe DNS, RDAP & Lexical Threat Heuristics
* **Safe Non-Intrusive DNS:** Queries standard DNS records (`A`, `AAAA`, `MX`, `NS`, `TXT`) asynchronously without visiting or executing untrusted domains.
* **ICANN RDAP Lookup:** Fetches registrar name, registration date, expiration date, and privacy proxy status.
* **Lexical Signals:** Calculates Shannon entropy for DGA detection, IDN Punycode indicators (`xn--`), subdomain depth, and typosquatting/lookalike patterns (e.g. `paypa1`, `micr0s0ft`).

### 6. 🕸️ Relational Threat Graph (NetworkX MultiDiGraph)
* **Graph Architecture:** Models complex infrastructure relationships across:
  - `EMAIL` $\to$ `SENDER` (`SENT_FROM`)
  - `SENDER` $\to$ `DOMAIN` (`ASSOCIATED_WITH`)
  - `EMAIL` $\to$ `URL` (`CONTAINS_URL`)
  - `URL` $\to$ `DOMAIN` / `IP` (`RESOLVES_TO`)
  - `EMAIL` $\to$ `IP` (`TRANSMITTED_VIA`)
  - `IP` $\to$ `ASN` (`HOSTED_ON_ASN`)
  - `IP` $\to$ `LOCATION` (`LOCATED_IN`)
* **Visual Graph Workspace:** Rendered interactively in the web UI using ReactFlow with zoom, pan, and node inspection.

### 7. 🔗 Cross-Case Campaign Correlation & Attribution
* **Automated Threat Clustering:** Queries historical cases in the persistent SQLite database to detect shared attack infrastructure (shared IPs, payload URLs, spoofed domains, or sender patterns).
* **Campaign Discovery:** Groups related attacks under unified Campaign IDs (e.g. `CAMPAIGN-8A19F230`).
* **Technical Attribution Hypotheses:** Evaluates evidence against structured threat hypotheses (`SPOOFED_IDENTITY`, `COMPROMISED_ACCOUNT`, `ANONYMIZED_INFRASTRUCTURE`, `SHARED_CAMPAIGN_INFRASTRUCTURE`).

### 8. 📄 Court-Grade PDF Forensic Report Generation
* **ReportLab Engine:** Generates tamper-evident forensic PDF incident reports with one click.
* **Evidence Chain of Custody:** Includes SHA-256 evidence digests, analyst session stamps, full header breakdowns, risk breakdown charts, observable tables, and legal limitations disclaimers.

---

## 💻 Tech Stack & Frameworks

| Layer | Technologies Used | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | FastAPI, Starlette, Uvicorn, Pydantic v2 | High-performance asynchronous REST API |
| **Machine Learning** | Scikit-Learn, SHAP, NumPy, SciPy, Joblib | Threat classification & explainability |
| **Graph Intelligence** | NetworkX | Relational infrastructure threat graph modeling |
| **Forensics & Network** | dnspython, tldextract, beautifulsoup4, httpx | Safe DNS, MIME parsing, RDAP, GeoIP |
| **PDF Generation** | ReportLab | Court-grade forensic incident reports |
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

## 🐳 Docker Deployment

DEEPTRACE uses a multi-stage Docker build that compiles the React frontend and packages it directly with the FastAPI backend into a single container:

```bash
# Build and run container
docker-compose up --build
```
Access the complete platform at `http://localhost:8000`.

---

## 🧪 Automated Testing

DEEPTRACE includes a comprehensive test suite covering all forensic, ML, graph, database, and API endpoints:

```bash
python -m pytest
```

```text
============================= test session starts =============================
platform win32 -- Python 3.10.0, pytest-9.1.1, pluggy-1.6.0
rootdir: DEEPTRACE
collected 53 items

tests\test_api.py ........                                               [ 15%]
tests\test_email_parser.py .......                                       [ 28%]
tests\test_intelligence_and_graph.py ..................                  [ 62%]
tests\test_ml_pipeline.py ............                                   [ 84%]
tests\test_soc_platform.py ........                                      [100%]

============================= 53 passed in 7.02s ==============================
```

---

## 🔒 Ethical Principles & Privacy Guarantees

1. **No External Body Transmission:** Raw email body content and confidential communications are **never** transmitted to third-party APIs.
2. **Safe Observable Queries:** Only discrete indicators (such as domain names, IP addresses, or URL hashes) are queried against threat intelligence providers.
3. **No Active Exploitation:** The platform never executes attachments or visits malicious URLs; all analysis is performed statically and safely.
4. **Admissibility & Non-Repudiation:** Every action is logged to an immutable audit ledger (`AuditLogRecord`) with cryptographic SHA-256 hash tracking.

---

## 👥 Smart India Hackathon 2026

* **Problem Statement:** SIH26106 — Email Threat Intelligence, Forensic Analysis & Relational Graph Platform
* **Team Name:** DEEP thinkers
* **Lead Developer / Author:** Rompicharla Siddharth ([@sidharth63](https://github.com/sidharth63))
* **Repository:** [https://github.com/sidharth63/SIH_26106](https://github.com/sidharth63/SIH_26106)
* **Production Deployment:** [https://sih-26106.onrender.com](https://sih-26106.onrender.com/)

---

<div align="center">

*Built with ❤️ and security engineering precision by Team DEEP thinkers.*

</div>
