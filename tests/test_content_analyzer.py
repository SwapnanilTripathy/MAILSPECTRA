import pytest
from backend.app.analyzers.content_analyzer import ContentIntelligenceAnalyzer
from backend.app.schemas.analysis import BodyContent
from backend.app.schemas.email import AddressEntity, AttachmentMetadata, EmailMetadata, ExtractedURL


def test_content_analyzer_urgency_detection():
    meta = EmailMetadata(
        from_sender=AddressEntity(address="alert@bank.com", domain="bank.com"),
        subject="URGENT: Immediate Action Required - Account Expiration Warning",
    )
    body = BodyContent(
        text_plain="Please act now within 24 hours. Final notice before account suspension.",
        text_plain_length=75,
        has_plain_text=True,
    )
    result = ContentIntelligenceAnalyzer.analyze(metadata=meta, body=body, urls=[], attachments=[])

    assert result.total_signals_detected >= 1
    categories = [s.category for s in result.signals]
    assert "URGENCY" in categories
    assert result.risk_score_contribution > 0


def test_content_analyzer_credential_harvesting_detection():
    meta = EmailMetadata(
        from_sender=AddressEntity(address="it@company.com", domain="company.com"),
        subject="Security Update: Verify Your Password",
    )
    body = BodyContent(
        text_plain="Please login to your portal and reset your credentials immediately to confirm your identity.",
        text_plain_length=95,
        has_plain_text=True,
    )
    result = ContentIntelligenceAnalyzer.analyze(metadata=meta, body=body, urls=[], attachments=[])

    categories = [s.category for s in result.signals]
    assert "CREDENTIALS" in categories
    cred_signal = next(s for s in result.signals if s.category == "CREDENTIALS")
    assert cred_signal.severity in ["HIGH", "CRITICAL"]
    assert cred_signal.confidence >= 0.75


def test_content_analyzer_financial_bec_detection():
    meta = EmailMetadata(
        from_sender=AddressEntity(address="ceo@victim-corp.com", domain="victim-corp.com"),
        subject="Confidential: Urgent Wire Transfer Required",
    )
    body = BodyContent(
        text_plain="Please execute the wire transfer for the overdue invoice. Attached are the new bank account routing numbers.",
        text_plain_length=110,
        has_plain_text=True,
    )
    result = ContentIntelligenceAnalyzer.analyze(metadata=meta, body=body, urls=[], attachments=[])

    categories = [s.category for s in result.signals]
    assert "FINANCIAL_BEC" in categories
    bec_signal = next(s for s in result.signals if s.category == "FINANCIAL_BEC")
    assert "wire transfer" in [m.lower() for m in bec_signal.matches] or "Wire transfer transaction reference" in bec_signal.matches


def test_content_analyzer_impersonation_cues():
    meta = EmailMetadata(
        from_sender=AddressEntity(address="executive@freemail.top", domain="freemail.top"),
        subject="Are you at your desk?",
    )
    body = BodyContent(
        text_plain="I am in a meeting with the Board of Directors. Please handle this personally as a strictly confidential request.",
        text_plain_length=115,
        has_plain_text=True,
    )
    result = ContentIntelligenceAnalyzer.analyze(metadata=meta, body=body, urls=[], attachments=[])

    categories = [s.category for s in result.signals]
    assert "IMPERSONATION" in categories


def test_content_analyzer_html_extraction():
    meta = EmailMetadata(
        from_sender=AddressEntity(address="support@helpdesk.com", domain="helpdesk.com"),
        subject="Mailbox Quota Exceeded",
    )
    body = BodyContent(
        text_html="<html><body><p>Your account has been <b>suspended</b> due to unauthorized access.</p><a href='http://1.2.3.4'>Click here</a></body></html>",
        text_html_length=120,
        has_html=True,
    )
    url = ExtractedURL(url="http://1.2.3.4/login", defanged_url="hxxp[://]1[.]2[.]3[.]4/login", is_ip_host=True, host="1.2.3.4")
    result = ContentIntelligenceAnalyzer.analyze(metadata=meta, body=body, urls=[url], attachments=[])

    categories = [s.category for s in result.signals]
    assert "SUSPENSION" in categories
    assert "URL_PATTERNS" in categories


def test_content_analyzer_benign_clean_content():
    meta = EmailMetadata(
        from_sender=AddressEntity(address="newsletter@engineering.org", domain="engineering.org"),
        subject="Monthly Engineering Digest: Distributed Systems",
    )
    body = BodyContent(
        text_plain="Hi team, here is the monthly update on our open-source distributed database roadmap and release notes.",
        text_plain_length=110,
        has_plain_text=True,
    )
    result = ContentIntelligenceAnalyzer.analyze(metadata=meta, body=body, urls=[], attachments=[])

    assert result.total_signals_detected == 0
    assert result.risk_score_contribution == 0.0
    assert result.highest_severity == "INFORMATIONAL"
