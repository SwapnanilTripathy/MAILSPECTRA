from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Literal
from fastapi import APIRouter, Request, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.logging import logger
from backend.app.core.assessment import severity_for_score
from backend.app.database.session import get_db
from backend.app.models.entities import AuditLogRecord, CaseRecord, ObservableRecord, TimelineEventRecord

router = APIRouter()


class CreateCaseRequest(BaseModel):
    case_id: Optional[str] = None
    filename: str
    subject: str = ""
    from_address: str = ""
    sender_domain: str = ""
    origin_ip: Optional[str] = None
    classification: str = "LEGITIMATE"
    risk_score: float = 0.0
    confidence: float = 1.0
    status: str = "OPEN"
    priority: str = "MEDIUM"
    assigned_to: Optional[str] = "SOC Analyst"
    tags: List[str] = Field(default_factory=list)
    sha256: str = ""
    full_analysis: Dict[str, Any] = Field(default_factory=dict)


class UpdateCaseStatusRequest(BaseModel):
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "ARCHIVED"]
    priority: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]] = None
    assigned_to: Optional[str] = None
    actor: str = "SOC Analyst"
    comment: Optional[str] = None


@router.get("", summary="List all investigation cases")
async def list_cases(
    db: AsyncSession = Depends(get_db),
    status_filter: Optional[str] = Query(None, alias="status"),
    classification_filter: Optional[str] = Query(None, alias="classification"),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    stmt = select(CaseRecord).order_by(desc(CaseRecord.created_at))

    if status_filter:
        stmt = stmt.where(CaseRecord.status == status_filter.upper())
    if classification_filter:
        stmt = stmt.where(CaseRecord.classification == classification_filter.upper())
    if search:
        search_pattern = f"%{search}%"
        stmt = stmt.where(
            (CaseRecord.case_id.ilike(search_pattern))
            | (CaseRecord.subject.ilike(search_pattern))
            | (CaseRecord.from_address.ilike(search_pattern))
            | (CaseRecord.filename.ilike(search_pattern))
            | (CaseRecord.sha256.ilike(search_pattern))
        )

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    cases = result.scalars().all()

    # Count total
    count_stmt = select(func.count(CaseRecord.case_id))
    if status_filter:
        count_stmt = count_stmt.where(CaseRecord.status == status_filter.upper())
    if classification_filter:
        count_stmt = count_stmt.where(CaseRecord.classification == classification_filter.upper())
    if search:
        count_stmt = count_stmt.where(
            (CaseRecord.case_id.ilike(search_pattern))
            | (CaseRecord.subject.ilike(search_pattern))
            | (CaseRecord.from_address.ilike(search_pattern))
            | (CaseRecord.filename.ilike(search_pattern))
            | (CaseRecord.sha256.ilike(search_pattern))
        )
    total_count = (await db.execute(count_stmt)).scalar() or 0

    return {
        "total": total_count,
        "items": [
            {
                "case_id": c.case_id,
                "filename": c.filename,
                "subject": c.subject,
                "from_address": c.from_address,
                "sender_domain": c.sender_domain,
                "origin_ip": c.origin_ip,
                "classification": c.classification,
                "risk_score": c.risk_score,
                "severity": severity_for_score(c.risk_score),
                "confidence": c.confidence,
                "status": c.status,
                "priority": c.priority,
                "assigned_to": c.assigned_to,
                "sha256": c.sha256,
                "report_sha256": c.report_sha256,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in cases
        ],
    }


@router.get("/{case_id}", summary="Get detailed investigation case")
async def get_case_detail(case_id: str, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(CaseRecord)
        .where(CaseRecord.case_id == case_id)
        .options(selectinload(CaseRecord.observables), selectinload(CaseRecord.timeline_events))
    )
    case_rec = (await db.execute(stmt)).scalar_one_or_none()

    if not case_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )

    # Parse full analysis JSON if available
    full_data = {}
    try:
        if case_rec.full_analysis_json:
            full_data = json.loads(case_rec.full_analysis_json)
    except Exception:
        pass

    return {
        "case_id": case_rec.case_id,
        "filename": case_rec.filename,
        "subject": case_rec.subject,
        "from_address": case_rec.from_address,
        "sender_domain": case_rec.sender_domain,
        "origin_ip": case_rec.origin_ip,
        "classification": case_rec.classification,
        "risk_score": case_rec.risk_score,
        "severity": severity_for_score(case_rec.risk_score),
        "confidence": case_rec.confidence,
        "status": case_rec.status,
        "priority": case_rec.priority,
        "assigned_to": case_rec.assigned_to,
        "sha256": case_rec.sha256,

        "report_sha256": case_rec.report_sha256,
        "report_generated_at": case_rec.report_generated_at.isoformat() if case_rec.report_generated_at else None,
        "created_at": case_rec.created_at.isoformat() if case_rec.created_at else None,
        "observables": [
            {
                "id": obs.id,
                "type": obs.observable_type,
                "value": obs.value,
                "defanged_value": obs.defanged_value,
                "source": obs.source,
            }
            for obs in case_rec.observables
        ],
        "timeline_events": [
            {
                "id": t.id,
                "event_type": t.event_type,
                "title": t.title,
                "description": t.description,
                "source": t.source,
                "timestamp": t.event_timestamp.isoformat() if t.event_timestamp else None,
            }
            for t in sorted(case_rec.timeline_events, key=lambda x: x.event_timestamp or datetime.min)
        ],
        "full_analysis": full_data,
    }


@router.post("", summary="Create new case record")
async def create_case(payload: CreateCaseRequest, db: AsyncSession = Depends(get_db)):
    case_id = payload.case_id or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{payload.sha256[:8].upper() or 'MANUAL'}"

    # Check if case exists
    existing = (await db.execute(select(CaseRecord).where(CaseRecord.case_id == case_id))).scalar_one_or_none()
    if existing:
        return {"status": "EXISTS", "case_id": case_id, "message": "Case already exists in database."}

    case_rec = CaseRecord(
        case_id=case_id,
        filename=payload.filename,
        subject=payload.subject,
        from_address=payload.from_address.lower(),
        sender_domain=payload.sender_domain.lower(),
        origin_ip=payload.origin_ip,
        classification=payload.classification,
        risk_score=payload.risk_score,
        confidence=payload.confidence,
        status=payload.status,
        priority=payload.priority,
        assigned_to=payload.assigned_to,
        tags_json=json.dumps(payload.tags),
        sha256=payload.sha256,
        full_analysis_json=json.dumps(payload.full_analysis),
    )
    db.add(case_rec)

    # Add initial timeline event
    db.add(
        TimelineEventRecord(
            case_id=case_id,
            event_type="CASE_CREATED",
            title="Investigation Case Created",
            description=f"Case opened with threat classification '{payload.classification}' and risk score {payload.risk_score}/100.",
            source="SOC_PLATFORM",
        )
    )

    # Add audit log
    db.add(
        AuditLogRecord(
            case_id=case_id,
            action="CASE_CREATED",
            actor=payload.assigned_to or "SOC Analyst",
            details=f"Created investigation case for file '{payload.filename}'",
        )
    )

    await db.commit()
    return {"status": "CREATED", "case_id": case_id}


@router.patch("/{case_id}/status", summary="Update investigation case status")
async def update_case_status(
    case_id: str,
    payload: UpdateCaseStatusRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    case_rec = (await db.execute(select(CaseRecord).where(CaseRecord.case_id == case_id))).scalar_one_or_none()
    if not case_rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found.")

    old_status = case_rec.status
    case_rec.status = payload.status.upper()
    if payload.priority:
        case_rec.priority = payload.priority.upper()
    if payload.assigned_to:
        case_rec.assigned_to = payload.assigned_to

    # Log timeline event
    db.add(
        TimelineEventRecord(
            case_id=case_id,
            event_type="CASE_STATUS_CHANGED",
            title=f"Case Status Updated to {case_rec.status}",
            description=f"Status changed from {old_status} to {case_rec.status}. {payload.comment or ''}".strip(),
            source=request.state.user.username,
        )
    )

    # Log audit event
    db.add(
        AuditLogRecord(
            case_id=case_id,
            action="CASE_STATUS_CHANGED",
            actor=request.state.user.username,
            details=f"Changed status from {old_status} to {case_rec.status}",
        )
    )

    await db.commit()
    return {"status": "UPDATED", "case_id": case_id, "new_status": case_rec.status}


@router.get("/{case_id}/evidence/verify")
async def verify_evidence(case_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    from pathlib import Path
    import hashlib
    from backend.app.core.config import settings
    from backend.app.models.entities import ArtifactRecord
    artifact = await db.scalar(select(ArtifactRecord).where(ArtifactRecord.case_id == case_id))
    if not artifact:
        raise HTTPException(404, "Original artifact unavailable for this case")
    path = Path(settings.UPLOAD_DIR).resolve() / artifact.storage_name
    if not path.is_file():
        raise HTTPException(404, "Original artifact storage is unavailable")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    db.add(AuditLogRecord(case_id=case_id, action="EVIDENCE_VERIFIED", actor=request.state.user.username, details="Digest comparison performed"))
    await db.commit()
    return {"artifact_id":artifact.artifact_id, "expected_sha256":artifact.sha256, "actual_sha256":actual, "integrity_verified":actual == artifact.sha256}


@router.get("/{case_id}/audit")
async def case_audit(case_id: str, db: AsyncSession = Depends(get_db)):
    if not await db.get(CaseRecord,case_id): raise HTTPException(404,"Case not found")
    rows=(await db.scalars(select(AuditLogRecord).where(AuditLogRecord.case_id==case_id).order_by(AuditLogRecord.id))).all()
    return {"items":[{"id":row.id,"action":row.action,"actor":row.actor,"details":row.details,"timestamp":row.created_at.isoformat()} for row in rows]}
