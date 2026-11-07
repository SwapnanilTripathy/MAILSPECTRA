<!-- coderabbit-ai-generated:v1 -->

# Analyst workflow

Log in with a provisioned account. Analyze `.eml` or raw RFC message text; the pipeline stores original bytes, complete versioned results, observables, timeline and alert in one database transaction. Re-uploading identical bytes reopens the existing analysis. Cases can be reopened in the investigation workspace without re-upload.

Dashboard alerts come from persistent database records. Analysts can acknowledge or resolve them; role checks and audit events apply. Case status/priority updates validate allowed values and record the authenticated actor rather than trusting a body-supplied actor string.

Privacy masking is shared across investigation, case/report lists, case detail, campaign detail and recent-case displays. It creates presentation copies and leaves source evidence unchanged. PDF generation can request masking; downloads while masking is on regenerate a masked report. This requires analyst permission. Masking is best-effort (email/IP/known display-name patterns), not a guarantee of anonymization or removal of all personal information in free text. Review exported evidence before sharing.

Reports use MAILSPECTRA branding and retain upstream attribution. Untrusted text is escaped before PDF markup rendering. The report includes the source digest, versioned evidence manifest, model caveat, reported/verified authentication, risk breakdown, relays, observables, provider statuses, campaign information and timeline. Large sections are explicitly truncated in the PDF; the persisted case retains full data. Report files have restricted permissions and random storage names.

The report digest is distributed in `GET /api/v1/reports/{case_id}/manifest`; embedding a PDF's own final digest in itself is not possible. `verify` recalculates the current PDF digest; original evidence has its own verification endpoint. Generation alone is never labelled verification. Download, verification, export and alert updates are audited. Audit records are application-managed, not an external immutable ledger.
