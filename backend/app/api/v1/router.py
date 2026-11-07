from fastapi import APIRouter, Depends
from backend.app.core.security import authorize
from backend.app.api.v1.endpoints import (
    intelligence,
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
private_router = APIRouter(dependencies=[Depends(authorize)])
private_router.include_router(analyze.router, tags=["Email Forensics & Analysis"])
private_router.include_router(alerts.router, prefix="/alerts", tags=["Threat Alerting"])
private_router.include_router(cases.router, prefix="/cases", tags=["Case Management"])
private_router.include_router(dashboard.router, prefix="/dashboard", tags=["SOC Dashboard"])
private_router.include_router(campaigns.router, prefix="/campaigns", tags=["Threat Campaigns"])
private_router.include_router(reports.router, prefix="/reports", tags=["Forensic Reports"])
private_router.include_router(system.router, prefix="/system", tags=["System & Settings"])


private_router.include_router(intelligence.router, prefix="/intelligence", tags=["Indicator intelligence"])
api_router.include_router(private_router)
