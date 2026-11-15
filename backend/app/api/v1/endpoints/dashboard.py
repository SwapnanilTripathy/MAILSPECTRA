from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import case as sql_case, desc, func, select
from sqlalchemy.orm import load_only
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.core.assessment import severity_for_score
from backend.app.core.config import settings
from backend.app.models.entities import CampaignRecord, CaseRecord

router = APIRouter()


@router.get("/overview", summary="Get the complete SOC dashboard snapshot")
async def get_dashboard_overview(db: AsyncSession = Depends(get_db)):
    """Return dashboard metrics, distributions and recent cases in one API response.

    This endpoint deliberately selects only the fields needed by the dashboard. In
    particular, it never loads the potentially large full_analysis_json case payload.
    """
    summary_stmt = select(
        func.count(CaseRecord.case_id),
        func.avg(CaseRecord.risk_score),
        func.sum(sql_case(
            (CaseRecord.risk_score >= settings.ALERT_THRESHOLD_SCORE, 1),
            else_=0,
        )),
        func.sum(sql_case(
            (CaseRecord.status.in_(["OPEN", "INVESTIGATING"]), 1),
            else_=0,
        )),
        select(func.count(CampaignRecord.campaign_id)).scalar_subquery(),
    )
    summary = (await db.execute(summary_stmt)).one()

    category_rows = (
        await db.execute(
            select(CaseRecord.classification, func.count(CaseRecord.case_id))
            .group_by(CaseRecord.classification)
        )
    ).all()
    class_counts = {name: int(count) for name, count in category_rows}

    severity_expression = sql_case(
        (CaseRecord.risk_score >= settings.CRITICAL_ALERT_SCORE, "CRITICAL"),
        (CaseRecord.risk_score >= settings.ALERT_THRESHOLD_SCORE, "HIGH"),
        (CaseRecord.risk_score >= 40, "MEDIUM"),
        (CaseRecord.risk_score >= 20, "LOW"),
        else_="INFORMATIONAL",
    )
    severity_rows = (
        await db.execute(
            select(severity_expression, func.count(CaseRecord.case_id))
            .group_by(severity_expression)
        )
    ).all()
    severity_counts = {name: int(count) for name, count in severity_rows}

    recent_rows = (
        await db.execute(
            select(
                CaseRecord.case_id,
                CaseRecord.filename,
                CaseRecord.subject,
                CaseRecord.from_address,
                CaseRecord.classification,
                CaseRecord.risk_score,
                CaseRecord.status,
                CaseRecord.sha256,
                CaseRecord.created_at,
            )
            .order_by(desc(CaseRecord.created_at))
            .limit(10)
        )
    ).all()

    stats = {
        "total_analyzed": int(summary[0] or 0),
        "threats_detected": sum(
            count for name, count in class_counts.items()
            if name not in {"LEGITIMATE", "BENIGN", "UNKNOWN"}
        ),
        "critical_threats": int(summary[2] or 0),
        "phishing_count": class_counts.get("PHISHING", 0) + class_counts.get("CREDENTIAL_HARVESTING", 0),
        "bec_count": class_counts.get("BUSINESS_EMAIL_COMPROMISE", 0),
        "impersonation_count": class_counts.get("IMPERSONATION", 0),
        "fraud_count": class_counts.get("FRAUD", 0),
        "suspicious_count": class_counts.get("SUSPICIOUS", 0),
        "legitimate_count": class_counts.get("LEGITIMATE", 0) + class_counts.get("BENIGN", 0),
        "active_campaigns": int(summary[4] or 0),
        "open_cases": int(summary[3] or 0),
        "average_risk_score": round(float(summary[1] or 0.0), 1),
    }
    categories = [
        {"name": name, "value": count}
        for name, count in category_rows
    ]
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    risk_distribution = [
        {"name": name, "value": severity_counts[name]}
        for name in severity_order
        if severity_counts.get(name, 0) > 0
    ]
    recent_items = [
        {
            "case_id": row.case_id,
            "filename": row.filename,
            "subject": row.subject or "No Subject",
            "from_address": row.from_address,
            "classification": row.classification,
            "risk_score": row.risk_score,
            "severity": severity_for_score(row.risk_score),
            "status": row.status,
            "sha256": row.sha256,
            "analyzed_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in recent_rows
    ]

    return {
        "stats": stats,
        "distribution": {
            "category_distribution": categories,
            "risk_distribution": risk_distribution,
        },
        "recent": {"items": recent_items},
    }


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
    stmt = (
        select(CaseRecord)
        .options(load_only(
            CaseRecord.case_id,
            CaseRecord.filename,
            CaseRecord.subject,
            CaseRecord.from_address,
            CaseRecord.classification,
            CaseRecord.risk_score,
            CaseRecord.status,
            CaseRecord.sha256,
            CaseRecord.created_at,
        ))
        .order_by(desc(CaseRecord.created_at))
        .limit(10)
    )
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

    # Aggregate severity counts in SQL rather than loading every risk score into Python.
    severity_expression = sql_case(
        (CaseRecord.risk_score >= settings.CRITICAL_ALERT_SCORE, "CRITICAL"),
        (CaseRecord.risk_score >= settings.ALERT_THRESHOLD_SCORE, "HIGH"),
        (CaseRecord.risk_score >= 40, "MEDIUM"),
        (CaseRecord.risk_score >= 20, "LOW"),
        else_="INFORMATIONAL",
    )
    severity_rows = (
        await db.execute(
            select(severity_expression, func.count(CaseRecord.case_id))
            .group_by(severity_expression)
        )
    ).all()
    severity_bands = {name: int(count) for name, count in severity_rows}
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    risk_distribution = [
        {"name": name, "value": severity_bands[name]}
        for name in severity_order
        if severity_bands.get(name, 0) > 0
    ]

    return {
        "category_distribution": categories,
        "risk_distribution": risk_distribution,
    }
