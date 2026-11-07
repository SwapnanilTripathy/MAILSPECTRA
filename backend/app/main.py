import os
import uuid
import time
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.database.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}...")
    logger.info(f"Team: {settings.TEAM_NAME} | Problem Statement: {settings.PROBLEM_STATEMENT}")
    await init_db()
    logger.info("Database ready")

    yield

    logger.info(f"Shutting down {settings.PROJECT_NAME}...")


def create_application() -> FastAPI:
    """FastAPI Application factory."""
    app = FastAPI(
        title=f"{settings.PROJECT_NAME} - Forensic Email Threat Intelligence Platform",
        description=(
            "**MAILSPECTRA** is an email threat analysis and infrastructure investigation workbench, "
            "and digital forensics intelligence platform built for SIH26106 by Team DEEP thinkers."
        ),
        version=settings.VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = uuid.uuid4().hex
        started = time.monotonic()
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > (settings.MAX_UPLOAD_SIZE_MB+1)*1024*1024):
            return JSONResponse(status_code=413, content={"detail":"Request body exceeds limit", "code":"PAYLOAD_TOO_LARGE", "request_id":request_id})
        try:
            response = await call_next(request)
        except Exception:
            logger.error("request_failed request_id=%s",request_id)
            response = JSONResponse(status_code=500,content={"detail":"Internal operation failed", "code":"INTERNAL_ERROR", "request_id":request_id})
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith(settings.API_V1_STR): response.headers["Cache-Control"] = "no-store"
        logger.info("request_completed request_id=%s method=%s status=%s duration_ms=%d",request_id,request.method,response.status_code,(time.monotonic()-started)*1000)
        return response

    from backend.app.core.request_limits import RequestBodyLimit
    app.add_middleware(RequestBodyLimit, max_bytes=(settings.MAX_UPLOAD_SIZE_MB + 1) * 1024 * 1024)

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API Router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    # Check for compiled frontend distribution
    frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
    assets_dir = os.path.join(frontend_dist, "assets")

    if os.path.isdir(frontend_dist):
        if os.path.isdir(assets_dir):
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        @app.get("/", summary="Root Platform Information")
        async def root(request: Request):
            accept_header = request.headers.get("accept", "")
            if "text/html" in accept_header and os.path.exists(os.path.join(frontend_dist, "index.html")):
                return FileResponse(os.path.join(frontend_dist, "index.html"))
            return JSONResponse(
                content={
                    "platform": settings.PROJECT_NAME,
                    "team": settings.TEAM_NAME,
                    "problem_statement": settings.PROBLEM_STATEMENT,
                    "status": "operational",
                    "version": settings.VERSION,
                    "documentation": "/docs",
                    "health_check": f"{settings.API_V1_STR}/health",
                    "analyze_endpoint": f"{settings.API_V1_STR}/analyze/email",
                }
            )

        @app.get("/{full_path:path}", summary="Serve Frontend SPA")
        async def serve_spa(full_path: str):
            if full_path.startswith("api/") or full_path == "docs" or full_path == "redoc" or full_path == "openapi.json":
                return JSONResponse(status_code=404, content={"detail": "Endpoint not found"})
            target = str((Path(frontend_dist) / full_path).resolve())
            if not Path(target).is_relative_to(Path(frontend_dist).resolve()):
                return JSONResponse(status_code=404,content={"detail":"Not found"})
            if full_path and os.path.exists(target) and os.path.isfile(target):
                return FileResponse(target)
            index_path = os.path.join(frontend_dist, "index.html")
            if os.path.exists(index_path):
                return FileResponse(index_path)
            return JSONResponse(status_code=404, content={"detail": "Not found"})
    else:
        @app.get("/", summary="Root Platform Information")
        async def root():
            return JSONResponse(
                content={
                    "platform": settings.PROJECT_NAME,
                    "team": settings.TEAM_NAME,
                    "problem_statement": settings.PROBLEM_STATEMENT,
                    "status": "operational",
                    "version": settings.VERSION,
                    "documentation": "/docs",
                    "health_check": f"{settings.API_V1_STR}/health",
                    "analyze_endpoint": f"{settings.API_V1_STR}/analyze/email",
                }
            )

    return app


app = create_application()

