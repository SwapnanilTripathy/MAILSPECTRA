import pytest
from httpx import ASGITransport, AsyncClient
from backend.app.main import app


@pytest.mark.asyncio
async def test_root_endpoint(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["platform"] == "DEEPTRACE"
        assert data["team"] == "DEEP thinkers"
        assert data["problem_statement"] == "SIH26106"
        assert data["status"] == "operational"


@pytest.mark.asyncio
async def test_health_endpoint(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "DEEPTRACE"
        assert "timestamp" in data


@pytest.mark.asyncio
async def test_analyze_email_upload_benign(benign_eml_bytes, auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        files = {
            "file": ("benign_standard.eml", benign_eml_bytes, "message/rfc822")
        }
        response = await client.post("/api/v1/analyze/email", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["case_id"].startswith("CASE-")
        assert data["metadata"]["subject"] == "Q3 Engineering Security Update & Best Practices"
        assert data["metadata"]["from_sender"]["address"] == "newsletter@legitcorp.com"
        assert data["authentication"]["spf_result"] == "pass"
        assert data["authentication"]["dkim_result"] == "pass"
        assert data["authentication"]["dmarc_result"] == "pass"
        assert len(data["relay_chain"]["hops"]) >= 2
        assert len(data["urls"]) >= 1
        assert data["threat_assessment"]["classification"] == "LEGITIMATE"


@pytest.mark.asyncio
async def test_analyze_email_upload_phishing(phishing_eml_bytes, auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        files = {
            "file": ("phishing_credential_harvest.eml", phishing_eml_bytes, "message/rfc822")
        }
        response = await client.post("/api/v1/analyze/email", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["threat_assessment"]["classification"] == "PHISHING"
        assert data["threat_assessment"]["risk_score"] >= 70.0
        assert any(u["is_ip_host"] for u in data["urls"])


@pytest.mark.asyncio
async def test_analyze_email_upload_spoofed(spoofed_eml_bytes, auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        files = {
            "file": ("spoofed_spf_fail.eml", spoofed_eml_bytes, "message/rfc822")
        }
        response = await client.post("/api/v1/analyze/email", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["metadata"]["from_sender"]["address"] == "ceo@victim-corp.com"
        assert len(data["attachments"]) == 1
        assert data["attachments"][0]["filename"] == "Overdue_Invoice_Payment.docm"
        assert data["attachments"][0]["is_suspicious_extension"] is True
        assert data["threat_assessment"]["risk_score"] >= 60.0


@pytest.mark.asyncio
async def test_analyze_empty_file_error(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        files = {
            "file": ("empty.eml", b"", "message/rfc822")
        }
        response = await client.post("/api/v1/analyze/email", files=files)
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_analyze_raw_empty_payload_error(auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        payload = {"raw_content": "   ", "filename": "empty.eml"}
        response = await client.post("/api/v1/analyze/raw", json=payload)
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_analyze_raw_payload(auth_headers):
    raw_eml = """From: sender@test.com
To: recipient@test.com
Subject: Quick Test
Date: Sun, 30 Aug 2026 00:00:00 +0000

This is a test message body.
"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        payload = {"raw_content": raw_eml, "filename": "test.eml"}
        response = await client.post("/api/v1/analyze/raw", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["metadata"]["subject"] == "Quick Test"
        assert data["metadata"]["from_sender"]["address"] == "sender@test.com"


