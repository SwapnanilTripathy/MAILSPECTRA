from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.database.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}...")
    logger.info(f"Team: {settings.TEAM_NAME} | Problem Statement: {settings.PROBLEM_STATEMENT}")
    logger.info(f"Database URL: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")
    
    # Initialize database tables
    try:
        await init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization warning: {e}")

    yield

    logger.info(f"Shutting down {settings.PROJECT_NAME}...")


def create_application() -> FastAPI:
    """FastAPI Application factory."""
    app = FastAPI(
        title=f"{settings.PROJECT_NAME} - Forensic Email Threat Intelligence Platform",
        description=(
            "**DEEPTRACE** is an AI-powered email threat analysis, infrastructure geolocation, "
            "and digital forensics intelligence platform built for SIH26106 by Team DEEP thinkers."
        ),
        version=settings.VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
    )

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
