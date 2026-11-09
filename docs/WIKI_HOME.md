# Welcome to the MAILSPECTRA Wiki!

Welcome to the official project knowledge base for **MAILSPECTRA** — an email forensics and AI-powered threat intelligence platform.

This Wiki is intended to explain the project, document its architecture and investigation workflows, track development progress, and record technical decisions.

> **Documentation principle:** Clearly distinguish implemented capabilities, verified findings, planned improvements, and open research questions. Do not present roadmap items as completed features.

## What is MAILSPECTRA?

MAILSPECTRA aims to help security analysts investigate suspicious emails by combining email forensics, threat intelligence, machine-learning-assisted analysis, evidence correlation, and analyst-facing investigation tools.

The project is intended to support workflows for:
- Security Operations Center (SOC) analysts.
- Digital forensic investigators.
- Incident response teams.
- Security researchers and developers.

## Start here

| Topic | Repository documentation |
|---|---|
| System architecture | [Architecture](ARCHITECTURE.md) |
| Email forensics | [Email Forensics](EMAIL_FORENSICS.md) |
| Analyst workflow | [Analyst Workflow](ANALYST_WORKFLOW.md) |
| API reference | [API](API.md) |
| Threat graph and correlation | [Graph and Correlation](GRAPH_AND_CORRELATION.md) |
| Threat intelligence providers | [Intelligence Providers](INTELLIGENCE_PROVIDERS.md) |
| ML model information | [ML Model Card](ML_MODEL_CARD.md) |
| Risk scoring | [Risk Scoring](RISK_SCORING.md) |
| Evidence handling | [Evidence and Chain of Custody](EVIDENCE_AND_CHAIN_OF_CUSTODY.md) |
| Security | [Security](SECURITY.md) and [Threat Model](THREAT_MODEL.md) |
| Testing | [Testing](TESTING.md) |
| Deployment | [Deployment](DEPLOYMENT.md) |
| Current project phases | [Phase Status](PHASE_STATUS.md) |
| Gap tracking | [Gap Closure Status](GAP_CLOSURE_STATUS.md) |
| Baseline review | [Baseline Audit](BASELINE_AUDIT.md) |

## Development roadmap and research

The following GitHub Issues capture the current improvement discussions and implementation work. Their contents are proposals and investigation tasks unless explicitly marked complete.

1. [#14 — Audit and upgrade the AI/ML architecture](../issues/14)
2. [#15 — Build a larger, reliable, leakage-resistant email dataset](../issues/15)
3. [#16 — Evaluate pretrained LLMs, advanced NLP, and hybrid threat analysis](../issues/16)
4. [#17 — Validate live GeoIP, IP reputation, and origin assessment](../issues/17)
5. [#18 — Design a SOC-scale interactive threat graph](../issues/18)
6. [#19 — Implement evidence-based email campaign correlation](../issues/19)
7. [#20 — Improve the forensic investigation dashboard](../issues/20)
8. [#21 — Production readiness, monitoring, security, and scalability](../issues/21)

## Core engineering principles

### 1. Evidence before conclusions
Keep raw email evidence, parsed observations, third-party intelligence, model predictions, and analyst conclusions distinct.

### 2. Explainable AI
A classifier provides predictions; explainability tools such as SHAP can describe feature contributions. Neither a prediction nor an explanation is proof of malicious activity.

### 3. Careful threat attribution
IP geolocation generally describes network infrastructure, not the physical location or identity of an attacker. Record provider, timestamp, uncertainty, and limitations.

### 4. Evidence-based campaign correlation
Do not group emails solely because they share a sender. Use multiple independent signals such as content similarity, URLs, domains, IPs, attachment hashes, headers, and timing. Preserve analyst review and override capability.

### 5. Privacy and safe handling
Treat email bodies, attachments, URLs, and headers as untrusted and potentially sensitive data. Do not commit private mailbox contents, credentials, tokens, or secrets to the repository.

### 6. Measured scalability
Evaluate graph libraries, databases, queues, and infrastructure against realistic workloads before adopting additional complexity.

## Current status

Use [Phase Status](PHASE_STATUS.md) and [Gap Closure Status](GAP_CLOSURE_STATUS.md) as the repository's current status references. Update them only after implementation and verification. Do not infer that a planned feature is complete merely because it appears in this Wiki or roadmap.

## How to contribute to this documentation

- Keep pages focused on one topic.
- Link related architecture notes, issues, pull requests, and tests.
- Include source-code paths for implementation-specific claims.
- Record assumptions and unresolved questions.
- Update status only when work is verified.
- Avoid duplicating detailed content that already exists in the `docs/` directory; link to the canonical document instead.

## Discussions and collaboration

Use [GitHub Discussions](https://github.com/SwapnanilTripathy/MAILSPECTRA/discussions) for open-ended ideas, design debates, research, and decisions.

Use [GitHub Issues](https://github.com/SwapnanilTripathy/MAILSPECTRA/issues) for actionable tasks, bugs, and tracked improvements.

Use Pull Requests to propose and review code or documentation changes.

---

*MAILSPECTRA — Email Forensics & AI-Powered Threat Intelligence.*
