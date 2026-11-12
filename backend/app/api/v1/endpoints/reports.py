from datetime import datetime, timezone
import asyncio
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from fastapi.responses import Response
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.logging import logger
from backend.app.database.session import get_db
from backend.app.models.entities import AuditLogRecord, CaseRecord, TimelineEventRecord
from backend.app.services.artifact_storage import ArtifactStorageError, delete_object, get_bytes, put_bytes
from backend.app.services.report_generator import ForensicReportGenerator

router = APIRouter()


async def _read_report_object(location: str) -> bytes:
    """Read a new object key or a legacy absolute local path."""
    if os.path.isabs(location):
        legacy_path = Path(location)
        if not legacy_path.is_file():
            raise FileNotFoundError(location)
        return await asyncio.to_thread(legacy_path.read_bytes)
    return await asyncio.to_thread(get_bytes, location)


def _attachment_headers(filename: str) -> dict:
    safe_name = Path(filename).name.replace('"', "").replace("\\", "_")
    return {"Content-Disposition": f'attachment; filename="{safe_name}"'}


@router.post("/generate/{case_id}", summary="Generate evidence-preserving PDF forensic report")
async def generate_case_report(case_id: str, request: Request, mask_pii: bool = Query(False), db: AsyncSession = Depends(get_db)):
    """Generate a PDF, persist it in private storage, and record its SHA-256."""
    stmt = select(CaseRecord).where(CaseRecord.case_id == case_id).options(
        selectinload(CaseRecord.observables), selectinload(CaseRecord.timeline_events)
    )
    case_rec = (await db.execute(stmt)).scalar_one_or_none()
    if not case_rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found.")

    case_dict: Dict[str, Any] = {
        "case_id": case_rec.case_id, "filename": case_rec.filename, "subject": case_rec.subject,
        "from_address": case_rec.from_address, "sender_domain": case_rec.sender_domain,
        "origin_ip": case_rec.origin_ip, "classification": case_rec.classification,
        "risk_score": case_rec.risk_score, "confidence": case_rec.confidence,
        "status": case_rec.status, "sha256": case_rec.sha256,
    }
    try:
        if case_rec.full_analysis_json:
            case_dict.update(json.loads(case_rec.full_analysis_json))
    except (TypeError, ValueError):
        logger.warning("Stored analysis JSON could not be decoded for case %s", case_id)

    case_dict["timeline"] = [
        {"action": row.event_type, "timestamp": row.event_timestamp.isoformat(), "description": row.description}
        for row in case_rec.timeline_events
    ]
    if mask_pii:
        from backend.app.services.privacy_service import PrivacyService
        case_dict = PrivacyService.redact_analysis(case_dict)

    report_key = None
    manifest_key = None
    try:
        # ReportLab needs a local output path; only the completed bytes are persisted.
        with tempfile.TemporaryDirectory(prefix="mailspectra-report-") as temp_dir:
            report_meta = ForensicReportGenerator.generate_case_pdf(case_dict, output_dir=temp_dir)
            pdf_bytes = await asyncio.to_thread(Path(report_meta["filepath"]).read_bytes)

        report_key = f"reports/{uuid.uuid4().hex}/{report_meta['filename']}"
        # Case IDs originate from the database; the storage adapter rejects traversal keys.
        await asyncio.to_thread(put_bytes, report_key, pdf_bytes, "application/pdf")

        manifest = {
            "schema_version": "1.1",
            "integrity_status": "PRESENT_UNVERIFIED",
            "integrity_limitation": "No independently stored manifest digest; PDF and original checks are separate",
            "generated_by": "MAILSPECTRA",
            "case_id": case_id,
            "report_sha256": report_meta["sha256"],
            "original_sha256": case_rec.sha256,
            "generated_at": report_meta["generated_at"],
            "privacy_redaction_applied": mask_pii,
            "evidence_manifest": case_dict.get("evidence_manifest", {}),
        }
        manifest_key = report_key + ".manifest.json"
        manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
        await asyncio.to_thread(put_bytes, manifest_key, manifest_bytes, "application/json")

        case_rec.report_path = report_key
        case_rec.report_sha256 = report_meta["sha256"]
        case_rec.report_generated_at = datetime.now(timezone.utc)
        db.add(TimelineEventRecord(
            case_id=case_id, event_type="REPORT_GENERATED", title="Forensic PDF Report Generated",
            description=f"Generated PDF artifact ({report_meta['filename']}) with SHA-256 hash {report_meta['sha256']}.",
            source="REPORT_GENERATOR",
        ))
        db.add(AuditLogRecord(
            case_id=case_id, action="REPORT_GENERATED", actor=request.state.user.username,
            details=f"Generated forensic report '{report_meta['filename']}'",
        ))
        await db.commit()
    except Exception as exc:
        await db.rollback()
        for object_key in (manifest_key, report_key):
            if object_key:
                try:
                    await asyncio.to_thread(delete_object, object_key)
                except Exception as cleanup_error:
                    logger.error("Report cleanup failed (%s)", type(cleanup_error).__name__)
        logger.error("Report persistence failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Report generation or persistence failed")

    return {
        "status": "SUCCESS", "case_id": case_id, "filename": report_meta["filename"],
        "filesize_bytes": report_meta["filesize_bytes"], "sha256": report_meta["sha256"],
        "generated_at": report_meta["generated_at"], "download_url": f"/api/v1/reports/{case_id}/download",
    }


@router.get("/{case_id}/download", summary="Download generated PDF report")
async def download_case_report(case_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    case_rec = await db.scalar(select(CaseRecord).where(CaseRecord.case_id == case_id))
    if not case_rec or not case_rec.report_path:
        raise HTTPException(status_code=404, detail="Forensic report not generated yet.")
    try:
        report_bytes = await _read_report_object(case_rec.report_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Forensic report file is unavailable.")
    except ArtifactStorageError:
        logger.error("Report storage read failed for case %s", case_id)
        raise HTTPException(status_code=503, detail="Report storage is temporarily unavailable")

    db.add(AuditLogRecord(case_id=case_id, action="REPORT_DOWNLOADED", actor=request.state.user.username, details="Authenticated PDF download"))
    await db.commit()
    filename = Path(case_rec.report_path).name
    return Response(content=report_bytes, media_type="application/pdf", headers=_attachment_headers(filename))


@router.get("/{case_id}/verify", summary="Verify forensic report cryptographic SHA-256 integrity")
async def verify_report_integrity(case_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    case_rec = await db.scalar(select(CaseRecord).where(CaseRecord.case_id == case_id))
    if not case_rec or not case_rec.report_path:
        raise HTTPException(status_code=404, detail="No generated report found for this case.")
    try:
        report_bytes = await _read_report_object(case_rec.report_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="No generated report found for this case.")
    except ArtifactStorageError:
        logger.error("Report storage verification read failed for case %s", case_id)
        raise HTTPException(status_code=503, detail="Report storage is temporarily unavailable")

    actual_hash = hashlib.sha256(report_bytes).hexdigest()
    is_valid = actual_hash == case_rec.report_sha256
    db.add(AuditLogRecord(case_id=case_id, action="REPORT_VERIFIED", actor=request.state.user.username, details="MATCH" if is_valid else "MISMATCH"))
    await db.commit()
    return {
        "case_id": case_id, "stored_hash": case_rec.report_sha256, "calculated_hash": actual_hash,
        "integrity_verified": is_valid, "status": "VERIFIED_INTACT" if is_valid else "INTEGRITY_COMPROMISED",
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
                "case_id": c.case_id, "filename": c.filename, "subject": c.subject,
                "classification": c.classification, "risk_score": c.risk_score,
                "report_filename": Path(c.report_path).name if c.report_path else "report.pdf",
                "report_sha256": c.report_sha256,
                "generated_at": c.report_generated_at.isoformat() if c.report_generated_at else None,
                "download_url": f"/api/v1/reports/{c.case_id}/download",
            }
            for c in cases
        ],
    }


@router.get("/{case_id}/manifest")
async def report_manifest(case_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    case_rec = await db.get(CaseRecord, case_id)
    if not case_rec or not case_rec.report_path:
        raise HTTPException(404, "Report unavailable")
    try:
        manifest_bytes = await _read_report_object(case_rec.report_path + ".manifest.json")
    except FileNotFoundError:
        raise HTTPException(404, "Manifest unavailable for this legacy report")
    except ArtifactStorageError:
        logger.error("Manifest storage read failed for case %s", case_id)
        raise HTTPException(503, "Manifest storage is temporarily unavailable")
    db.add(AuditLogRecord(case_id=case_id, action="MANIFEST_EXPORTED", actor=request.state.user.username, details="Report manifest download"))
    await db.commit()
    return Response(content=manifest_bytes, media_type="application/json", headers=_attachment_headers("mailspectra-manifest.json"))
