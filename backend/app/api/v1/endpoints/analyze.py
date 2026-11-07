from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.database.session import get_db
from backend.app.schemas.analysis import EmailAnalysisResponse
from backend.app.services.privacy_service import PrivacyService
from backend.app.services.threat_pipeline import pipeline

router = APIRouter()


class RawEmailAnalyzeRequest(BaseModel):
    raw_content: str = Field(..., description="Raw RFC 822 / MIME .eml email string")
    filename: Optional[str] = "raw_input.eml"
    mask_pii: bool = False


@router.post(
    "/analyze/email",
    response_model=EmailAnalysisResponse,
    summary="Analyze .EML file for forensic intelligence, AI threat prediction, threat graph & campaign correlation",
    description="Upload a raw .eml file to extract forensic metadata, calculate AI threat classification, compute transparent risk score, build threat graph, and correlate campaigns.",
)
async def analyze_email_file(
    file: UploadFile = File(..., description="The .eml email artifact file to analyze"),
    mask_pii: bool = Query(False, description="Optionally mask email addresses and IP addresses in presentation view"),
    db: AsyncSession = Depends(get_db),
) -> EmailAnalysisResponse:
    # Validate extension / file
    filename = file.filename or "uploaded.eml"
    if not (filename.lower().endswith(".eml") or filename.lower().endswith(".msg") or filename.lower().endswith(".txt")):
        logger.warning(f"File uploaded with non-standard extension: {filename}")

    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Failed to read uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file: {str(e)}",
        )

    # Size limit validation
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB",
        )

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty.",
        )

    logger.info(f"Analyzing uploaded email artifact: '{filename}' ({len(content)} bytes)")
    try:
        analysis_result = await pipeline.analyze_bytes_async(raw_bytes=content, filename=filename, db_session=db)
        if mask_pii or settings.PRIVACY_MASKING_ENABLED:
            analysis_result = PrivacyService.apply_to_response(analysis_result)
            analysis_result.privacy_redaction_applied = True
        pred_cls = analysis_result.ai_inference.predicted_class if analysis_result.ai_inference else "UNKNOWN"
        risk_sc = analysis_result.risk_assessment.risk_score if analysis_result.risk_assessment else 0.0
        logger.info(f"Analysis completed: Case ID {analysis_result.case_id} | AI Class: {pred_cls} | Risk: {risk_sc}/100")
        return analysis_result
    except Exception as e:
        logger.error(f"Error during email forensic & AI analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic & AI analysis error: {str(e)}",
        )


@router.post(
    "/analyze/raw",
    response_model=EmailAnalysisResponse,
    summary="Analyze raw .EML string content with AI prediction, threat graph & correlation",
    description="Analyze raw RFC 822 / MIME text content sent in JSON payload with full forensic and threat intelligence.",
)
async def analyze_raw_email(
    payload: RawEmailAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
) -> EmailAnalysisResponse:
    if not payload.raw_content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="raw_content string cannot be empty.",
        )

    raw_bytes = payload.raw_content.encode("utf-8", errors="replace")
    logger.info(f"Analyzing raw email payload ({len(raw_bytes)} bytes)")

    try:
        res = await pipeline.analyze_bytes_async(raw_bytes=raw_bytes, filename=payload.filename, db_session=db)
        if payload.mask_pii or settings.PRIVACY_MASKING_ENABLED:
            res = PrivacyService.apply_to_response(res)
            res.privacy_redaction_applied = True
        return res
    except Exception as e:
        logger.error(f"Error during raw email parsing: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic & AI analysis error: {str(e)}",
        )



