# MAILSPECTRA, derived from DEEPTRACE / SIH26106; see LICENSE and README attribution.
FROM node:24-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim AS runner
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=10001:10001 backend/ ./backend/
COPY --chown=10001:10001 migrations/ ./migrations/
COPY --chown=10001:10001 alembic.ini ./
COPY --chown=10001:10001 scripts/start.sh ./scripts/start.sh
COPY --chown=10001:10001 --from=frontend-builder /app/frontend/dist ./frontend/dist
RUN useradd --uid 10001 --create-home mailspectra && mkdir -p /app/storage/uploads /app/storage/reports && chown -R mailspectra:mailspectra /app/storage
USER mailspectra
ENV PYTHONUNBUFFERED=1 APP_ENV=production DEBUG=false HOST=0.0.0.0 PORT=8000 INTELLIGENCE_MODE=offline UPLOAD_DIR=/app/storage/uploads REPORTS_DIR=/app/storage/reports
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/ready', timeout=3)"
CMD ["sh", "scripts/start.sh"]
