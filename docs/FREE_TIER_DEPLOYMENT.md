# Free-tier deployment (demo / evaluation)

This guide deploys the existing single-container MAILSPECTRA application to a Render Free web service and uses Supabase Free for PostgreSQL and private object storage.

> **Demo-only warning:** free services can sleep, pause, restart, and run out of quota. Do not use this setup for real incident response, regulated data, customer mailboxes, or evidence that requires guaranteed retention, availability, or chain of custody. The project’s current ML corpus is a 21-sample demonstration corpus and its probabilities are uncalibrated; review the ML model card before presenting model performance.

## What persists where

| Component | Provider | Free-tier limitation |
|---|---|---|
| Web app + API | Render Free Docker web service | 512 MB RAM; sleeps after 15 minutes idle; ephemeral filesystem; cold start |
| PostgreSQL | Supabase Free | 500 MB per project; project can pause after one week of inactivity |
| Original .eml, PDF reports, manifests | Supabase Storage private bucket | 1 GB file storage; 5 GB egress |
| ML explanation | Heuristic fallback on Render Free | SHAP_ENABLED=false to reduce memory use; classifier predictions remain enabled |

Render Free does not support persistent disks. Files must not be stored on its local filesystem. Supabase Free includes 500 MB database storage and 1 GB file storage; free projects may pause after a week of inactivity. Check provider dashboards for current quotas before deploying.

## 1. Create a Supabase Free project

1. Create a project on the Supabase Free plan. Select a strong database password and keep it in a password manager.
2. In Storage, create a bucket named mailspectra-evidence.
3. Keep the bucket **private**. Do not make evidence files public.
4. In Project Settings → API, copy the Project URL and the service-role key. The service-role key bypasses Storage access policies, so use it only as a backend secret. Never put it in frontend code, Git, a public issue, or a chat.
5. In Project Settings → Database, copy the PostgreSQL **Session pooler** connection string. Replace the placeholder password with the database password you chose. Keep the SSL requirement (sslmode=require).

## 2. Create the Render Blueprint

1. Merge the free-tier deployment PR into main after reviewing its CI checks.
2. In Render, open **Blueprints → New Blueprint Instance** and select this repository.
3. Select the main branch and render.yaml.
4. Review that the only Render resource is a web service with plan free. There should be no Render Postgres resource and no persistent disk.
5. Before the first deploy, set these manual environment values on the Render service:

| Environment variable | Value |
|---|---|
| DATABASE_URL | Supabase Session pooler PostgreSQL URL |
| SUPABASE_URL | Supabase Project URL |
| SUPABASE_SERVICE_ROLE_KEY | Supabase service-role key |
| SUPABASE_BUCKET | mailspectra-evidence (already set by the Blueprint) |
| EVIDENCE_STORAGE_BACKEND | supabase (already set by the Blueprint) |

The Blueprint generates SECRET_KEY for the app. It keeps INTELLIGENCE_MODE=offline, sets SHAP_ENABLED=false for the 512 MB service, and serves the compiled frontend and API from the same origin. Do not set CORS_ORIGINS=*.

6. Trigger the first deploy. The configured start command runs Alembic migrations before starting the FastAPI app.
7. Check https://<your-service>.onrender.com/api/v1/ready. Expect HTTP 200 with database available, Supabase storage configured, and schema revision 0003.

## 3. Verify the evidence workflow

1. Sign in and upload a synthetic .eml test message.
2. Confirm the analysis response includes the original artifact SHA-256.
3. Open the case and run Verify Evidence. It should return integrity_verified: true.
4. Generate the forensic PDF report.
5. Download the report and verify that the SHA-256 endpoint reports VERIFIED_INTACT.
6. Download the manifest and confirm it contains the original and report digests.
7. In Supabase Storage, verify that the evidence objects are present in the private bucket.

## 4. Free-tier caveats and safety

- Render Free sleeps after 15 minutes without inbound traffic; first requests after sleep may take about a minute to start.
- Render Free files disappear on restart, redeploy, and spin-down. This deployment stores originals, reports, and manifests in Supabase Storage.
- Supabase Free projects can pause after one week of inactivity. Resume the project in the Supabase dashboard if this happens.
- Supabase Free does not provide the paid-plan backup and recovery guarantees. Export the database and evidence objects separately before relying on this demo.
- Watch database size (500 MB), object storage (1 GB), egress (5 GB), Render instance hours, bandwidth, and build minutes. Do not upgrade to a paid resource to resolve a quota prompt; stop and review usage first.
- A Supabase service-role key has broad privileges. Rotate it immediately if exposed.
- Use synthetic or sanitized emails only. The app is a research/demo platform, not a certified forensic evidence repository.
