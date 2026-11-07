import os
import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.main import app
from backend.app.services.report_generator import ForensicReportGenerator


@pytest.mark.asyncio
async def test_1_dashboard_stats_endpoint(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        resp = await client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_analyzed" in data
        assert "threats_detected" in data
        assert "critical_threats" in data
        assert "active_campaigns" in data


@pytest.mark.asyncio
async def test_2_dashboard_distribution_endpoint(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        resp = await client.get("/api/v1/dashboard/distribution")
        assert resp.status_code == 200
        data = resp.json()
        assert "category_distribution" in data
        assert "risk_distribution" in data


@pytest.mark.asyncio
async def test_3_case_creation_and_retrieval(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        case_payload = {
            "case_id": "CASE-TEST-0001",
            "filename": "suspicious_test.eml",
            "subject": "Wire Transfer Urgent",
            "from_address": "ceo@impersonated.com",
            "sender_domain": "impersonated.com",
            "origin_ip": "198.51.100.25",
            "classification": "BUSINESS_EMAIL_COMPROMISE",
            "risk_score": 85.5,
            "confidence": 0.92,
            "status": "OPEN",
            "priority": "HIGH",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        }
        create_resp = await client.post("/api/v1/cases", json=case_payload)
        assert create_resp.status_code == 200

        # Retrieve case
        get_resp = await client.get("/api/v1/cases/CASE-TEST-0001")
        assert get_resp.status_code == 200
        case_data = get_resp.json()
        assert case_data["case_id"] == "CASE-TEST-0001"
        assert case_data["classification"] == "BUSINESS_EMAIL_COMPROMISE"
        assert len(case_data["timeline_events"]) >= 1


@pytest.mark.asyncio
async def test_4_case_status_update(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        patch_resp = await client.patch(
            "/api/v1/cases/CASE-TEST-0001/status",
            json={"status": "INVESTIGATING", "priority": "CRITICAL", "comment": "Assigned to Tier 2 triage."},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["new_status"] == "INVESTIGATING"

        # Verify updated status
        get_resp = await client.get("/api/v1/cases/CASE-TEST-0001")
        assert get_resp.json()["status"] == "INVESTIGATING"
        assert get_resp.json()["priority"] == "CRITICAL"


@pytest.mark.asyncio
async def test_5_report_generation_and_integrity_verification(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        # Generate report
        gen_resp = await client.post("/api/v1/reports/generate/CASE-TEST-0001")
        assert gen_resp.status_code == 200
        gen_data = gen_resp.json()
        assert gen_data["status"] == "SUCCESS"
        assert len(gen_data["sha256"]) == 64
        assert gen_data["filename"].endswith(".pdf")

        # Verify report cryptographic hash
        verify_resp = await client.get("/api/v1/reports/CASE-TEST-0001/verify")
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["integrity_verified"] is True
        assert verify_data["status"] == "VERIFIED_INTEACT"


@pytest.mark.asyncio
async def test_6_report_download(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        dl_resp = await client.get("/api/v1/reports/CASE-TEST-0001/download")
        assert dl_resp.status_code == 200
        assert dl_resp.headers["content-type"] == "application/pdf"
        assert len(dl_resp.content) > 1000


@pytest.mark.asyncio
async def test_7_auth_login(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "test-admin", "password": "test-only-long-password"},
        )
        assert login_resp.status_code == 200
        data = login_resp.json()
        assert "access_token" in data
        assert data["user"]["username"] == "test-admin"


@pytest.mark.asyncio
async def test_8_system_status_and_settings(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        status_resp = await client.get("/api/v1/system/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["database"]["status"] == "CONNECTED"

        settings_resp = await client.get("/api/v1/system/settings")
        assert settings_resp.status_code == 200
        assert "project_name" in settings_resp.json()
        # Verify no secret API keys leaked in response
        assert "secret_key" not in str(settings_resp.json()).lower()
