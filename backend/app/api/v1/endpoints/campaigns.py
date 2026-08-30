from datetime import datetime
import json
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.models.entities import CampaignRecord, CaseRecord

router = APIRouter()


@router.get("", summary="List all active threat campaigns")
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    stmt = select(CampaignRecord).order_by(desc(CampaignRecord.last_seen))
    campaigns = (await db.execute(stmt)).scalars().all()

    items = []
    for c in campaigns:
        member_ids = []
        shared_infra = {}
        try:
            member_ids = json.loads(c.member_case_ids_json)
        except Exception:
            pass
        try:
            shared_infra = json.loads(c.shared_indicators_json)
        except Exception:
            pass

        items.append({
            "campaign_id": c.campaign_id,
            "name": c.name,
            "primary_threat_type": c.primary_threat_type,
            "confidence": c.confidence,
            "member_count": len(member_ids),
            "member_case_ids": member_ids,
            "shared_infrastructure": shared_infra,
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        })

    return {"total": len(items), "items": items}


@router.get("/{campaign_id}", summary="Get detailed campaign cluster")
async def get_campaign_detail(campaign_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(CampaignRecord).where(CampaignRecord.campaign_id == campaign_id)
    camp = (await db.execute(stmt)).scalar_one_or_none()

    if not camp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign '{campaign_id}' not found.")

    member_ids = []
    shared_infra = {}
    try:
        member_ids = json.loads(camp.member_case_ids_json)
    except Exception:
        pass
    try:
        shared_infra = json.loads(camp.shared_indicators_json)
    except Exception:
        pass

    # Fetch member cases
    cases_stmt = select(CaseRecord).where(CaseRecord.case_id.in_(member_ids))
    cases_orm = (await db.execute(cases_stmt)).scalars().all()

    member_cases = [
        {
            "case_id": c.case_id,
            "filename": c.filename,
            "subject": c.subject,
            "classification": c.classification,
            "risk_score": c.risk_score,
            "status": c.status,
            "from_address": c.from_address,
        }
        for c in cases_orm
    ]

    return {
        "campaign_id": camp.campaign_id,
        "name": camp.name,
        "primary_threat_type": camp.primary_threat_type,
        "confidence": camp.confidence,
        "shared_infrastructure": shared_infra,
        "first_seen": camp.first_seen.isoformat() if camp.first_seen else None,
        "last_seen": camp.last_seen.isoformat() if camp.last_seen else None,
        "member_cases": member_cases,
    }
