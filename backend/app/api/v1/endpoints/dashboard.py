from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.core.assessment import severity_for_score
from backend.app.core.config import settings
from backend.app.models.entities import CampaignRecord, CaseRecord

router = APIRouter()


@router.get("/stats", summary="Get aggregated SOC dashboard statistics")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Computes real database-derived statistics across all analyzed cases and campaigns."""
    # Total cases analyzed
    total_analyzed = (await db.execute(select(func.count(CaseRecord.case_id)))).scalar() or 0

    # Threat classification breakdown
    threat_query = select(CaseRecord.classification, func.count(CaseRecord.case_id)).group_by(CaseRecord.classification)
    threat_rows = (await db.execute(threat_query)).all()
    class_counts = {row[0]: row[1] for row in threat_rows}

    # Count specific threats
    phishing_count = class_counts.get("PHISHING", 0) + class_counts.get("CREDENTIAL_HARVESTING", 0)
    bec_count = class_counts.get("BUSINESS_EMAIL_COMPROMISE", 0)
    impersonation_count = class_counts.get("IMPERSONATION", 0)
    fraud_count = class_counts.get("FRAUD", 0)
    suspicious_count = class_counts.get("SUSPICIOUS", 0)
    legitimate_count = class_counts.get("LEGITIMATE", 0) + class_counts.get("BENIGN", 0)

    # Threats detected (all non-legitimate)
    threats_detected = sum(v for k, v in class_counts.items() if k not in {"LEGITIMATE", "BENIGN", "UNKNOWN"})

    # Critical / High severity cases
    crit_high_query = select(func.count(CaseRecord.case_id)).where(CaseRecord.risk_score >= settings.ALERT_THRESHOLD_SCORE)
    critical_threats = (await db.execute(crit_high_query)).scalar() or 0

    # Active campaigns count
    active_campaigns = (await db.execute(select(func.count(CampaignRecord.campaign_id)))).scalar() or 0

    # Open investigations count
    open_cases = (await db.execute(select(func.count(CaseRecord.case_id)).where(CaseRecord.status.in_(["OPEN", "INVESTIGATING"])))).scalar() or 0

    # Average risk score
    avg_risk = (await db.execute(select(func.avg(CaseRecord.risk_score)))).scalar() or 0.0

    return {
        "total_analyzed": total_analyzed,
        "threats_detected": threats_detected,
        "critical_threats": critical_threats,
        "phishing_count": phishing_count,
        "bec_count": bec_count,
        "impersonation_count": impersonation_count,
        "fraud_count": fraud_count,
        "suspicious_count": suspicious_count,
        "legitimate_count": legitimate_count,
        "active_campaigns": active_campaigns,
        "open_cases": open_cases,
        "average_risk_score": round(float(avg_risk), 1),
    }


@router.get("/recent", summary="Get recent investigations list")
async def get_recent_investigations(db: AsyncSession = Depends(get_db)):
    """Retrieve 10 most recent email investigations."""
    stmt = select(CaseRecord).order_by(desc(CaseRecord.created_at)).limit(10)
    cases = (await db.execute(stmt)).scalars().all()

    return {
        "items": [
            {
                "case_id": c.case_id,
                "filename": c.filename,
                "subject": c.subject or "No Subject",
                "from_address": c.from_address,
                "classification": c.classification,
                "risk_score": c.risk_score,
                "severity": severity_for_score(c.risk_score),
                "status": c.status,
                "sha256": c.sha256,
                "analyzed_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in cases
        ]
    }


@router.get("/distribution", summary="Get threat category and risk level distribution")
async def get_distribution(db: AsyncSession = Depends(get_db)):
    """Retrieve classification distribution and severity risk bands for SOC dashboard charts."""
    # Threat Categories
    cat_stmt = select(CaseRecord.classification, func.count(CaseRecord.case_id)).group_by(CaseRecord.classification)
    cat_rows = (await db.execute(cat_stmt)).all()
    categories = [{"name": row[0], "value": row[1]} for row in cat_rows]

    # Risk Severity Bands
    cases = (await db.execute(select(CaseRecord.risk_score))).scalars().all()
    severity_bands = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for score in cases:
        severity_bands[severity_for_score(score)] += 1

    risk_distribution = [{"name": k, "value": v} for k, v in severity_bands.items() if v > 0]

    return {
        "category_distribution": categories,
        "risk_distribution": risk_distribution,
    }
