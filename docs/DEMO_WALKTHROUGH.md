# MAILSPECTRA demo walkthrough

This guide walks through a repeatable local demonstration using the bundled synthetic email messages. It is intended for product walkthroughs, classroom demonstrations, and development testing—not for assessing real emails or measuring detection accuracy.

## Safety and scope

- All sender, recipient, and host names in this demo set use the reserved `.test` namespace.
- All IPv4 literals are from RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- The only attachment is a plain-text synthetic note. There are no executables, macros, real credentials, or customer records.
- Message URLs are indicators for display only. Do not click or fetch them.
- The `Authentication-Results` and `Received-SPF` fields are claims embedded in the sample messages. A saved `.eml` cannot establish that those claims were produced by a trusted receiving mail server.
- Use the default `INTELLIGENCE_MODE=offline` setting and a disposable local database/storage directory. Do not mix demo cases with real investigation evidence.

The canonical sample inventory and limitations are in [data/demo/manifest.json](../data/demo/manifest.json). The three files used by the UI are in [frontend/public/demo-samples](../frontend/public/demo-samples).

## 1. Start a local instance

Follow the complete prerequisite and installation instructions in the [main README](../README.md#12-local-development-setup). Copy `.env.example` to `.env`, then configure dedicated demo-only database and evidence-storage paths **before applying migrations or starting the backend**:

```dotenv
DATABASE_URL=sqlite+aiosqlite:///./mailspectra-demo.db
UPLOAD_DIR=./demo-data/uploads
REPORTS_DIR=./demo-data/reports
INTELLIGENCE_MODE=offline
VERIFY_AUTHENTICATION_DNS=false
```

The Quick Demo analysis request preserves the uploaded artifact and analysis during ingestion, before the separate **Save Case** action. Use a disposable database and storage directories; do not mix synthetic demo cases with real investigations or point the demo at an existing evidence store. Keep this local `.env` uncommitted.

Apply migrations and provision an administrator, then create an analyst account:

```bash
python -m alembic upgrade head
python -m backend.app.manage_users demo-admin --role admin
python -m backend.app.manage_users demo-analyst --role analyst
```

The user-management command prompts for passwords interactively. Do not put passwords in shell history or this guide.

Start the backend and frontend in two terminals, from the repository root:

```bash
# Terminal 1
python backend/run.py

# Terminal 2
npm --prefix frontend run dev -- --host 0.0.0.0
```

Open [http://localhost:3000](http://localhost:3000) and sign in as `demo-analyst`. The local API health and readiness endpoints are `http://localhost:8000/api/v1/health` and `http://localhost:8000/api/v1/ready`.

## 2. Run the three Quick Demos

Open **Investigate**. Under **Quick Demos**, choose one of the three scenarios. The UI fetches the exact same committed `.eml` assets that are available for manual file upload; it does not construct a second inline version of each message.

| UI button | Bundled file | What to investigate |
|---|---|---|
| Benign | [benign_newsletter.eml](../frontend/public/demo-samples/benign_newsletter.eml) | Newsletter context, low-pressure language, a `.test` URL, and supplied authentication pass claims |
| Phishing | [credential_harvest.eml](../frontend/public/demo-samples/credential_harvest.eml) | Urgency, credential-verification language, sender/Reply-To mismatch, URL/IP indicators, and supplied authentication failure claims |
| Spoofed BEC | [executive_payment_request.eml](../frontend/public/demo-samples/executive_payment_request.eml) | Executive display-name claim, sender/Reply-To mismatch, payment pressure, and plain-text attachment metadata |

For a manual upload demonstration, download one of the sample files from the repository and use **File Upload (.EML)** instead of a Quick Demo button. The file contents should produce the same analysis input.

## 3. Review the analysis

After a sample finishes processing, use the investigation panels to tell a coherent evidence story:

1. **Summary and verdict.** Show the classification, severity, risk score, and bounded evidence contributions. Explain that the score is a heuristic decision-support value, not a calibrated probability.
2. **Headers and authentication.** Compare the sender, Return-Path, and Reply-To fields. Separate reported authentication claims from independently verified results. In this saved-message demo, the embedded claims are not trusted proof; SPF may be unavailable because trusted SMTP peer/envelope context is not present.
3. **Relay path.** Review the observed relay entries and distinguish message-supplied hops from independently established acquisition context.
4. **Observables and content.** Inspect defanged URLs, domains, IP literals, and attachment metadata. Do not open the links. No attachment is executed.
5. **Infrastructure and intelligence.** With offline mode enabled, explain that fixture/unavailable states are not live provider reputation. A missing lookup is not a clean verdict.
6. **Threat graph and campaign correlation.** Run more than one sample to give the workspace multiple cases to compare. Shared observable/time relationships are investigative leads—not proof of common ownership, actor identity, or attribution.

Do not promise a specific class, score, severity, or graph relationship for a sample. The bundled ML model is demonstration-only and uncalibrated; outputs are expected to depend on the model/rule pipeline version.

## 4. Preserve the case and export a report

From the investigation view:

1. Save the analysis as a case using the case action.
2. Generate/export the forensic PDF report.
3. Open **Cases** or **Reports** to locate the persisted case and generated report.
4. Use the report verification action to recompute the PDF's SHA-256 and compare it with the stored report digest.
5. Use the original-evidence verification action on the case to recompute the digest of the preserved uploaded message.
6. Inspect the report manifest where needed. The manifest labels its integrity as `PRESENT_UNVERIFIED` because there is no independently stored manifest digest.

A matching hash demonstrates that the current bytes match the digest stored by this application. It does not prove who sent the email, how it was acquired, or that an administrator could not alter both the file and its stored digest. The application audit log is not an external immutable ledger.

For API-level exploration, see [docs/API.md](API.md). Useful endpoints include:

- `POST /api/v1/analyze/email` — upload an RFC 5322/MIME `.eml` file.
- `POST /api/v1/analyze/raw` — submit raw message text.
- `POST /api/v1/cases` — persist a case record.
- `GET /api/v1/cases/{case_id}/evidence/verify` — recalculate the original evidence digest.
- `POST /api/v1/reports/generate/{case_id}` — generate the PDF and manifest.
- `GET /api/v1/reports/{case_id}/verify` — recalculate the generated PDF digest.
- `GET /api/v1/reports/{case_id}/manifest` — retrieve the report manifest.

All private API routes require an authenticated user with the appropriate role.

## 5. Suggested presentation sequence

A concise five-to-seven-minute presentation can follow this order:

1. Introduce MAILSPECTRA as an analyst workbench, not an automated mail gateway.
2. Run the benign newsletter to show the normal analysis interface.
3. Run credential harvesting and focus on urgency, reply mismatch, URLs, and the separation of reported versus verified authentication.
4. Run the executive payment request and point out the plain-text attachment metadata without executing anything.
5. Save one case, generate its report, and show both report and original-artifact digest verification.
6. Close with the ML, provider, attribution, and evidence-integrity limitations.

## 6. Capture real product screenshots

The repository does not currently bundle verified screenshots of a running MAILSPECTRA instance. Do not substitute mockups or generated illustrations and label them as product screenshots.

Once the app is running locally with only the synthetic demo cases loaded, capture:

- Dashboard showing the synthetic case/alert overview.
- Investigation summary for the credential-harvesting sample.
- Header/authentication panel showing the distinction between reported and verified results.
- Threat graph after multiple synthetic cases have been saved.
- Generated PDF report and its verification result.

Before committing screenshots, check every visible email address, message body, URL, and report field. Keep the screenshot set limited to the synthetic demo environment; never capture real customer evidence, browser credentials, tokens, or environment values.
