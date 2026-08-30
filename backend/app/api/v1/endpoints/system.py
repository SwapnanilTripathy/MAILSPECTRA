from typing import Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.database.session import get_db

router = APIRouter()


@router.get("/status", summary="System Health & Operational Status")
async def get_system_status(db: AsyncSession = Depends(get_db)):
    db_status = "CONNECTED"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "DISCONNECTED"

    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.APP_ENV,
        "team": settings.TEAM_NAME,
        "problem_statement": settings.PROBLEM_STATEMENT,
        "database": {
            "status": db_status,
            "type": "SQLite / PostgreSQL Compatible",
        },
        "intelligence_mode": settings.INTELLIGENCE_MODE.upper(),
        "providers": {
            "geoip": "ACTIVE (Offline Fixtures & MaxMind/IPInfo Protocol)",
            "dns": "ACTIVE (Asynchronous dnspython Resolver)",
            "rdap": "ACTIVE (Official ICANN/RIR HTTPS RDAP Client)",
            "threat_intel": "ACTIVE" if (settings.VIRUSTOTAL_API_KEY or settings.ABUSEIPDB_API_KEY) else "OFFLINE_DATABASE",
            "threat_graph": "ACTIVE (NetworkX MultiDiGraph Engine)",
            "ml_engine": "ACTIVE (Logistic Regression + Linear SHAP)",
        },
        "privacy": {
            "masking_available": True,
            "payload_execution_sandbox": "DISABLED_FOR_SAFETY",
            "body_transmission_to_third_parties": "DISABLED",
        },
    }


@router.get("/settings", summary="Retrieve non-sensitive platform configuration")
async def get_system_settings():
    return {
        "project_name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "intelligence_mode": settings.INTELLIGENCE_MODE,
        "dns_timeout_seconds": settings.DNS_TIMEOUT_SECONDS,
        "http_timeout_seconds": settings.HTTP_INTEL_TIMEOUT_SECONDS,
        "cache_ttl_hours": settings.CACHE_TTL_HOURS,
        "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_MB,
        "has_virustotal_key": bool(settings.VIRUSTOTAL_API_KEY),
        "has_abuseipdb_key": bool(settings.ABUSEIPDB_API_KEY),
        "has_ipinfo_key": bool(settings.IPINFO_TOKEN),
    }
