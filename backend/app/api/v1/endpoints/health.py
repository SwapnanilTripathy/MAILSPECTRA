from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.database.session import get_db
from backend.app.core.config import settings

router = APIRouter()


@router.get("/health", summary="Service Health Check")
async def health_check():
    """Returns the operational status, version, and platform metadata."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "team": settings.TEAM_NAME,
        "problem_statement": settings.PROBLEM_STATEMENT,
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def ready(db: AsyncSession = Depends(get_db)):
    from pathlib import Path
    import tempfile
    try:
        await db.execute(text("SELECT 1"))
        revision = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar()
        if revision != "0002": raise RuntimeError("Migration required")
        for directory in (settings.UPLOAD_DIR, settings.REPORTS_DIR):
            Path(directory).mkdir(parents=True,exist_ok=True,mode=0o700)
            with tempfile.TemporaryFile(dir=directory) as stream: stream.write(b'readiness')
    except Exception:
        return JSONResponse(status_code=503,content={"status":"not_ready"})
    return {"status":"ready", "database":"available", "storage":"writable", "schema_revision":revision}
