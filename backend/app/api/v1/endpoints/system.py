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

    from backend.app.ml.model_loader import ModelLoader
    model_available = ModelLoader.load_model() is not None
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
            "geoip": "CONFIGURED_NOT_CHECKED" if settings.INTELLIGENCE_MODE == "live" and settings.IPINFO_TOKEN else "OFFLINE_OR_UNAVAILABLE",
            "dns": "CONFIGURED_NOT_CHECKED" if settings.INTELLIGENCE_MODE == "live" else "OFFLINE_FIXTURES",
            "rdap": "CONFIGURED_NOT_CHECKED" if settings.INTELLIGENCE_MODE == "live" else "OFFLINE_FIXTURES",
            "threat_intel": "CONFIGURED_NOT_CHECKED" if settings.INTELLIGENCE_MODE == "live" and settings.ABUSEIPDB_API_KEY else "OFFLINE_OR_UNAVAILABLE",
            "threat_graph": "ACTIVE (NetworkX MultiDiGraph Engine)",
            "ml_engine": "AVAILABLE_DEMONSTRATION_MODEL" if model_available else "UNAVAILABLE_RULE_FALLBACK",
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
        "virustotal_status": "NOT_IMPLEMENTED",
        "shodan_status": "NOT_IMPLEMENTED",
        "has_abuseipdb_key": bool(settings.ABUSEIPDB_API_KEY),
        "has_ipinfo_key": bool(settings.IPINFO_TOKEN),
    }
