import pytest
from backend.app.schemas.analysis import BodyContent, EmailAnalysisResponse, InitialThreatAssessment
from backend.app.schemas.email import AddressEntity, AuthenticationSummary, EmailMetadata, EvidenceHashes, ExtractedIP, RelayChainSummary
from backend.app.services.alert_service import AlertService
from backend.app.services.privacy_service import PrivacyService


def test_privacy_service_email_masking():
    assert PrivacyService.mask_email("user@example.com") == "u**r@example.com"
    assert PrivacyService.mask_email("john.doe@company.org") == "j******e@company.org"
    assert PrivacyService.mask_email("ab@test.com") == "a*@test.com"
    assert PrivacyService.mask_email("") == ""


def test_privacy_service_ip_masking():
    assert PrivacyService.mask_ip("198.51.100.25") == "198.51.***.***"
    assert PrivacyService.mask_ip("203.0.113.88") == "203.0.***.***"
    assert PrivacyService.mask_ip("127.0.0.1") == "127.0.***.***"
    assert PrivacyService.mask_ip("") == ""


def test_privacy_service_name_masking():
    assert PrivacyService.mask_name("John Doe") == "J**n D*e"
    assert PrivacyService.mask_name("Executive") == "E*******e"
    assert PrivacyService.mask_name("") == ""


def test_privacy_service_apply_to_response():
    resp = EmailAnalysisResponse(
        case_id="CASE-12345",
        analyzed_at="2026-09-01T12:00:00Z",
        filename="test.eml",
        file_size_bytes=1024,
        evidence_hashes=EvidenceHashes(md5="123", sha1="456", sha256="789"),
        metadata=EmailMetadata(
            from_sender=AddressEntity(display_name="David Miller", address="david.miller@corp.com", domain="corp.com"),
            to_recipients=[AddressEntity(display_name="Jane Doe", address="jane.doe@corp.com", domain="corp.com")],
            return_path="bounce@corp.com",
        ),
        authentication=AuthenticationSummary(),
        relay_chain=RelayChainSummary(origin_ip="198.51.100.45", defanged_origin_ip="198.51.100.45"),
        ips=[ExtractedIP(ip="198.51.100.45", defanged_ip="198.51.100.45")],
        body=BodyContent(text_plain="Hello", has_plain_text=True),
        threat_assessment=InitialThreatAssessment(risk_score=10.0, classification="BENIGN"),
    )

    masked_resp = PrivacyService.apply_to_response(resp)
    assert "@corp.com" in masked_resp.metadata.from_sender.address
    assert "*" in masked_resp.metadata.from_sender.address
    assert masked_resp.relay_chain.origin_ip == "198.51.***.***"
    assert masked_resp.ips[0].ip == "198.51.***.***"


def test_alert_service_high_threat_trigger():
    resp = EmailAnalysisResponse(
        case_id="CASE-CRIT-99",
        analyzed_at="2026-09-01T12:00:00Z",
        filename="urgent_phish.eml",
        file_size_bytes=2048,
        evidence_hashes=EvidenceHashes(md5="111", sha1="222", sha256="333"),
        metadata=EmailMetadata(
            from_sender=AddressEntity(display_name="Bank Security", address="alert@badbank.com", domain="badbank.com"),
            subject="URGENT: Immediate Account Verification Required",
        ),
        authentication=AuthenticationSummary(dmarc_result="fail", spf_result="fail"),
        relay_chain=RelayChainSummary(),
        body=BodyContent(text_plain="Verify password immediately", has_plain_text=True),
        threat_assessment=InitialThreatAssessment(risk_score=85.0, classification="PHISHING"),
    )

    eval_result = AlertService.evaluate_analysis(resp)
    assert eval_result.is_alert_generated is True
    assert eval_result.alert is not None
    assert eval_result.alert.severity == "CRITICAL"
    assert eval_result.alert.requires_immediate_action is True
    assert eval_result.alert.risk_score == 85.0
    assert len(eval_result.alert.triggers) >= 1
    assert len(eval_result.alert.recommended_actions) >= 1


def test_alert_service_benign_no_immediate_action():
    resp = EmailAnalysisResponse(
        case_id="CASE-BENIGN-01",
        analyzed_at="2026-09-01T12:00:00Z",
        filename="benign.eml",
        file_size_bytes=512,
        evidence_hashes=EvidenceHashes(md5="aaa", sha1="bbb", sha256="ccc"),
        metadata=EmailMetadata(
            from_sender=AddressEntity(display_name="Newsletter", address="info@news.org", domain="news.org"),
            subject="Weekly Digest",
        ),
        authentication=AuthenticationSummary(dmarc_result="pass", spf_result="pass"),
        relay_chain=RelayChainSummary(),
        body=BodyContent(text_plain="Here is your weekly update.", has_plain_text=True),
        threat_assessment=InitialThreatAssessment(risk_score=5.0, classification="BENIGN"),
    )

    eval_result = AlertService.evaluate_analysis(resp)
    assert eval_result.is_alert_generated is False
    assert eval_result.alert is None
