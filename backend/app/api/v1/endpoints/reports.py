from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import FileResponse
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.database.session import get_db
from backend.app.models.entities import AuditLogRecord, CaseRecord, TimelineEventRecord
from backend.app.services.report_generator import ForensicReportGenerator

router = APIRouter()


@router.post("/generate/{case_id}", summary="Generate evidence-preserving PDF forensic report")
async def generate_case_report(case_id: str, request: Request, mask_pii: bool = Query(False), db: AsyncSession = Depends(get_db)):

    """Generates PDF forensic report, computes SHA-256 cryptographic hash, and updates case record."""
    stmt = (
        select(CaseRecord)
        .where(CaseRecord.case_id == case_id)
        .options(selectinload(CaseRecord.observables), selectinload(CaseRecord.timeline_events))
    )
    case_rec = (await db.execute(stmt)).scalar_one_or_none()

    if not case_rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found.")

    # Parse full analysis data
    case_dict: Dict[str, Any] = {
        "case_id": case_rec.case_id,
        "filename": case_rec.filename,
        "subject": case_rec.subject,
        "from_address": case_rec.from_address,
        "sender_domain": case_rec.sender_domain,
        "origin_ip": case_rec.origin_ip,
        "classification": case_rec.classification,
        "risk_score": case_rec.risk_score,
        "confidence": case_rec.confidence,
        "status": case_rec.status,
        "sha256": case_rec.sha256,
    }

    try:
        if case_rec.full_analysis_json:
            full_json = json.loads(case_rec.full_analysis_json)
            case_dict.update(full_json)
    except Exception:
        pass

    case_dict["timeline"] = [{"action":row.event_type,"timestamp":row.event_timestamp.isoformat(),"description":row.description} for row in case_rec.timeline_events]
    if mask_pii:
        from backend.app.services.privacy_service import PrivacyService
        case_dict = PrivacyService.redact_analysis(case_dict)
    # Generate PDF
    try:
        report_meta = ForensicReportGenerator.generate_case_pdf(case_dict)
    except Exception as e:
        logger.error("Report generation failed: %s", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Report generation failed",
        )

    # Update CaseRecord with report details
    case_rec.report_path = report_meta["filepath"]
    case_rec.report_sha256 = report_meta["sha256"]
    case_rec.report_generated_at = datetime.now(timezone.utc)

    # Add timeline event
    db.add(
        TimelineEventRecord(
            case_id=case_id,
            event_type="REPORT_GENERATED",
            title="Forensic PDF Report Generated",
            description=f"Generated PDF artifact ({report_meta['filename']}) with SHA-256 hash {report_meta['sha256']}.",
            source="REPORT_GENERATOR",
        )
    )

    # Add audit log
    db.add(
        AuditLogRecord(
            case_id=case_id,
            action="REPORT_GENERATED",
            actor=request.state.user.username,
            details=f"Generated forensic report '{report_meta['filename']}'",
        )
    )

    manifest = {"generated_by":"MAILSPECTRA", "case_id":case_id, "report_sha256":report_meta["sha256"], "original_sha256":case_rec.sha256, "generated_at":report_meta["generated_at"], "privacy_redaction_applied":mask_pii, "evidence_manifest":case_dict.get("evidence_manifest",{})}
    manifest_path = report_meta["filepath"] + ".manifest.json"
    try:
        with open(manifest_path, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            json.dump(manifest, stream, indent=2)
        await db.commit()
    except Exception:
        await db.rollback()
        for path in (manifest_path, report_meta["filepath"]):
            if os.path.exists(path):
                os.unlink(path)
        raise HTTPException(500, "Report persistence failed")

    return {
        "status": "SUCCESS",
        "case_id": case_id,
        "filename": report_meta["filename"],
        "filesize_bytes": report_meta["filesize_bytes"],
        "sha256": report_meta["sha256"],
        "generated_at": report_meta["generated_at"],
        "download_url": f"/api/v1/reports/{case_id}/download",
    }


@router.get("/{case_id}/download", summary="Download generated PDF report")
async def download_case_report(case_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    stmt = select(CaseRecord).where(CaseRecord.case_id == case_id)
    case_rec = (await db.execute(stmt)).scalar_one_or_none()

    if not case_rec or not case_rec.report_path or not os.path.exists(case_rec.report_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic report not generated yet or file missing. Please click 'Generate Report' first.",
        )

    db.add(AuditLogRecord(case_id=case_id, action="REPORT_DOWNLOADED", actor=request.state.user.username, details="Authenticated PDF download"))
    await db.commit()
    filename = os.path.basename(case_rec.report_path)
    return FileResponse(
        path=case_rec.report_path,
        media_type="application/pdf",
        filename=filename,
    )


@router.get("/{case_id}/verify", summary="Verify forensic report cryptographic SHA-256 integrity")
async def verify_report_integrity(case_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    stmt = select(CaseRecord).where(CaseRecord.case_id == case_id)
    case_rec = (await db.execute(stmt)).scalar_one_or_none()

    if not case_rec or not case_rec.report_path or not os.path.exists(case_rec.report_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No generated report found for this case.",
        )

    # Recalculate file hash on disk
    with open(case_rec.report_path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()

    is_valid = actual_hash == case_rec.report_sha256
    db.add(AuditLogRecord(case_id=case_id,action="REPORT_VERIFIED",actor=request.state.user.username,details="MATCH" if is_valid else "MISMATCH"))
    await db.commit()

    return {
        "case_id": case_id,
        "stored_hash": case_rec.report_sha256,
        "calculated_hash": actual_hash,
        "integrity_verified": is_valid,
        "status": "VERIFIED_INTACT" if is_valid else "INTEGRITY_COMPROMISED",
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("", summary="List all generated forensic reports")
async def list_reports(db: AsyncSession = Depends(get_db)):
    stmt = select(CaseRecord).where(CaseRecord.report_sha256.is_not(None)).order_by(desc(CaseRecord.report_generated_at))
    cases = (await db.execute(stmt)).scalars().all()

    return {
        "total": len(cases),
        "items": [
            {
                "case_id": c.case_id,
                "filename": c.filename,
                "subject": c.subject,
                "classification": c.classification,
                "risk_score": c.risk_score,
                "report_filename": os.path.basename(c.report_path) if c.report_path else "report.pdf",
                "report_sha256": c.report_sha256,
                "generated_at": c.report_generated_at.isoformat() if c.report_generated_at else None,
                "download_url": f"/api/v1/reports/{c.case_id}/download",
            }
            for c in cases
        ],
    }


@router.get("/{case_id}/manifest")
async def report_manifest(case_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    case = await db.get(CaseRecord,case_id)
    if not case or not case.report_path: raise HTTPException(404,"Report unavailable")
    path = case.report_path + ".manifest.json"
    if not os.path.isfile(path): raise HTTPException(404,"Manifest unavailable for this legacy report")
    db.add(AuditLogRecord(case_id=case_id,action="MANIFEST_EXPORTED",actor=request.state.user.username,details="Report manifest download"))
    await db.commit()
    return FileResponse(path,media_type="application/json",filename="mailspectra-manifest.json")
