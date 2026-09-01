from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    alerts,
    analyze,
    auth,
    campaigns,
    cases,
    dashboard,
    health,
    reports,
    system,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["System Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(analyze.router, tags=["Email Forensics & Analysis"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Threat Alerting"])
api_router.include_router(cases.router, prefix="/cases", tags=["Case Management"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["SOC Dashboard"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["Threat Campaigns"])
api_router.include_router(reports.router, prefix="/reports", tags=["Forensic Reports"])
api_router.include_router(system.router, prefix="/system", tags=["System & Settings"])

