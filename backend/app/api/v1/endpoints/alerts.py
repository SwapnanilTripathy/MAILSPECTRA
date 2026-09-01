from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from backend.app.core.config import settings
from backend.app.services.alert_service import AlertService, SecurityAlert

router = APIRouter()


class AlertThresholdsConfig(BaseModel):
    high_threshold: float
    critical_threshold: float
    retention_days: int
    alerting_status: str


@router.get("", response_model=List[SecurityAlert], summary="Get recent high-risk alerts feed")
async def list_recent_alerts(limit: int = Query(20, ge=1, le=100)) -> List[SecurityAlert]:
    """Retrieve buffered real-time threat alerts from recent email ingestions."""
    return AlertService.get_recent_alerts(limit=limit)


@router.get("/config", response_model=AlertThresholdsConfig, summary="Get active alert thresholds")
async def get_alert_config() -> AlertThresholdsConfig:
    """Retrieve configured risk score threshold rules for automated alert generation."""
    return AlertThresholdsConfig(
        high_threshold=settings.ALERT_THRESHOLD_SCORE,
        critical_threshold=settings.CRITICAL_ALERT_SCORE,
        retention_days=settings.DEFAULT_DATA_RETENTION_DAYS,
        alerting_status="ACTIVE_AUTOMATED_EVALUATION",
    )
