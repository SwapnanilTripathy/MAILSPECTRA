from typing import List, Optional, Literal
from fastapi import APIRouter, Depends, Query, Request, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.database.session import get_db
from backend.app.models.entities import AlertRecord, AuditLogRecord

from backend.app.core.config import settings
from backend.app.services.alert_service import AlertService, SecurityAlert

router = APIRouter()


class AlertThresholdsConfig(BaseModel):
    high_threshold: float
    critical_threshold: float
    retention_days: int
    alerting_status: str


@router.get("", response_model=List[SecurityAlert], summary="Get recent high-risk alerts feed")
async def list_recent_alerts(limit: int = Query(20, ge=1, le=100), offset: int = Query(0,ge=0), db: AsyncSession = Depends(get_db)) -> List[SecurityAlert]:
    records = (await db.scalars(select(AlertRecord).order_by(AlertRecord.created_at.desc()).offset(offset).limit(limit))).all()
    return [SecurityAlert.model_validate_json(row.payload_json).model_copy(update={"status":row.status,"assigned_to":row.assigned_to}) for row in records]


@router.get("/config", response_model=AlertThresholdsConfig, summary="Get active alert thresholds")
async def get_alert_config() -> AlertThresholdsConfig:
    """Retrieve configured risk score threshold rules for automated alert generation."""
    return AlertThresholdsConfig(
        high_threshold=settings.ALERT_THRESHOLD_SCORE,
        critical_threshold=settings.CRITICAL_ALERT_SCORE,
        retention_days=settings.DEFAULT_DATA_RETENTION_DAYS,
        alerting_status="ACTIVE_AUTOMATED_EVALUATION",
    )


class AlertUpdate(BaseModel):
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]
    assigned_to: Optional[str] = None

@router.patch("/{alert_id}", response_model=SecurityAlert)
async def update_alert(alert_id: str, payload: AlertUpdate, request: Request, db: AsyncSession = Depends(get_db)):
    record = await db.get(AlertRecord,alert_id)
    if not record: raise HTTPException(404,"Alert not found")
    record.status = payload.status
    record.assigned_to = payload.assigned_to or request.state.user.username
    db.add(AuditLogRecord(case_id=record.case_id,action="ALERT_UPDATED",actor=request.state.user.username,details=record.status))
    await db.commit()
    return SecurityAlert.model_validate_json(record.payload_json).model_copy(update={"status":record.status,"assigned_to":record.assigned_to})
