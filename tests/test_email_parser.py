import pytest
from backend.app.services.email_parser import EmailForensicParser
from backend.app.utils.crypto import calculate_hashes, defang_ip, defang_url
from backend.app.utils.network import classify_ip, extract_ips_from_text, is_valid_ip


def test_crypto_and_defanging():
    test_bytes = b"DEEPTRACE FORENSIC TEST"
    hashes = calculate_hashes(test_bytes)
    assert len(hashes["sha256"]) == 64
    assert len(hashes["md5"]) == 32
    assert len(hashes["sha1"]) == 40

    assert defang_url("http://malicious-site.com/payload") == "hxxp://malicious-site[.]com/payload"
    assert defang_url("https://secure.bank.com/login") == "hxxps://secure[.]bank[.]com/login"
    assert defang_ip("198.51.100.45") == "198[.]51[.]100[.]45"


def test_network_utils():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("2001:db8::1") is True
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("not-an-ip") is False

    priv_class = classify_ip("192.168.1.10")
    assert priv_class["is_private"] is True
    assert priv_class["is_public"] is False

    pub_class = classify_ip("8.8.8.8")
    assert pub_class["is_public"] is True
    assert pub_class["is_private"] is False

    extracted = extract_ips_from_text("Connection from 198.51.100.25 to 10.0.1.50 at [203.0.113.88]")
    assert "198.51.100.25" in extracted
    assert "10.0.1.50" in extracted
    assert "203.0.113.88" in extracted


def test_benign_email_parsing(benign_eml_bytes):
    parser = EmailForensicParser(raw_bytes=benign_eml_bytes, filename="benign_standard.eml")
    result = parser.parse()

    assert result.success is True
    assert result.case_id.startswith("CASE-")
    assert result.file_size_bytes == len(benign_eml_bytes)
    assert result.evidence_hashes.sha256 != ""

    # Metadata assertions
    assert result.metadata.from_sender.address == "newsletter@legitcorp.com"
    assert result.metadata.from_sender.display_name == "LegitCorp Quarterly"
    assert result.metadata.subject == "Q3 Engineering Security Update & Best Practices"
    assert len(result.metadata.to_recipients) >= 1
    assert result.metadata.to_recipients[0].address == "victim-analyst@defense.org"

    # Authentication assertions
    assert result.authentication.spf_result == "pass"
    assert result.authentication.dkim_result == "pass"
    assert result.authentication.dmarc_result == "pass"

    # Relay chain assertions
    assert result.relay_chain.total_hops >= 2
    assert result.relay_chain.origin_ip == "10.0.1.50"  # No public hop in documentation-only fixture
    assert result.relay_chain.hops[0].is_origin_hop is True

    # Body assertions
    assert result.body.has_plain_text is True
    assert result.body.has_html is True
    assert "Hello Security Team" in result.body.text_plain

    # URL assertions
    assert len(result.urls) >= 1
    found_urls = [u.url for u in result.urls]
    assert any("https://docs.legitcorp.com/security/2026" in u for u in found_urls)

    # Threat assessment
    assert result.threat_assessment.classification == "BENIGN"
    assert result.threat_assessment.risk_score < 40.0


def test_phishing_email_parsing(phishing_eml_bytes):
    parser = EmailForensicParser(raw_bytes=phishing_eml_bytes, filename="phishing_credential_harvest.eml")
    result = parser.parse()

    assert result.success is True
    assert result.metadata.from_sender.address == "security-alert@global-banking-corp.com"
    assert result.metadata.return_path == "bounces@darkweb-relay.ru"
    assert len(result.metadata.reply_to) == 1
    assert result.metadata.reply_to[0].address == "harvest-collector@darkweb-relay.ru"

    # Authentication assertions
    assert result.authentication.spf_result == "fail"
    assert result.authentication.dkim_result == "fail"
    assert result.authentication.dmarc_result == "fail"

    # URL observables
    assert len(result.urls) >= 1
    ip_urls = [u for u in result.urls if u.is_ip_host]
    assert len(ip_urls) >= 1
    assert ip_urls[0].host == "198.51.100.45"
    assert ip_urls[0].defanged_url.startswith("hxxp://198[.]51[.]100[.]45")

    # Threat assessment assertions
    assert result.threat_assessment.classification == "PHISHING"
    assert result.threat_assessment.risk_score >= 70.0
    indicators = [ind.feature for ind in result.threat_assessment.indicators]
    assert "SPF_FAIL" in indicators
    assert "DKIM_FAIL" in indicators
    assert "DMARC_FAIL" in indicators
    assert "IP_BASED_URL" in indicators
    assert "DOMAIN_MISMATCH_RETURN_PATH" in indicators


def test_spoofed_attachment_email_parsing(spoofed_eml_bytes):
    parser = EmailForensicParser(raw_bytes=spoofed_eml_bytes, filename="spoofed_spf_fail.eml")
    result = parser.parse()

    assert result.success is True
    assert result.authentication.spf_result == "fail"
    assert result.metadata.from_sender.address == "ceo@victim-corp.com"
    assert result.metadata.return_path == "spoofed-bounce@attacker-hub.net"

    # Attachment assertions
    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename == "Overdue_Invoice_Payment.docm"
    assert att.extension == ".docm"
    assert att.is_suspicious_extension is True
    assert len(att.sha256) == 64

    # Threat assessment assertions
    assert result.threat_assessment.risk_score >= 60.0
    indicators = [ind.feature for ind in result.threat_assessment.indicators]
    assert "SUSPICIOUS_ATTACHMENT_EXTENSION" in indicators
    assert "SPF_FAIL" in indicators


def test_encoded_headers_and_recipients():
    raw = (
        b"From: =?utf-8?B?QWxleGFuZGVyIEfDvG50aGVy?= <alexander@domain.de>\n"
        b"To: User One <user1@target.com>, User Two <user2@target.com>\n"
        b"Cc: User Three <user3@target.com>\n"
        b"Bcc: Secret Audit <audit@target.com>\n"
        b"Subject: =?utf-8?Q?Sicherheitshinweis_=C3=9Cberweisung?=\n"
        b"Date: Sun, 30 Aug 2026 00:00:00 +0000\n"
        b"\n"
        b"Test body text\n"
    )
    parser = EmailForensicParser(raw_bytes=raw, filename="encoded.eml")
    result = parser.parse()

    assert result.metadata.from_sender.display_name == "Alexander Günther"
    assert result.metadata.from_sender.address == "alexander@domain.de"
    assert result.metadata.subject == "Sicherheitshinweis Überweisung"
    assert len(result.metadata.to_recipients) == 2
    assert len(result.metadata.cc_recipients) == 1
    assert len(result.metadata.bcc_recipients) == 1
    assert result.relay_chain.total_hops == 0


def test_html_form_and_img_urls():
    raw = (
        b"From: portal@services.net\n"
        b"To: target@corp.com\n"
        b"Subject: Form Action & Image Tracking\n"
        b"Content-Type: text/html; charset=utf-8\n"
        b"\n"
        b"<html><body>"
        b"<img src='https://tracker.analytics.com/pixel.png' />"
        b"<form action='http://phish-login.com/submit.php' method='POST'></form>"
        b"<a href='https://legit-cdn.org/styles.css'>styles</a>"
        b"</body></html>"
    )
    parser = EmailForensicParser(raw_bytes=raw, filename="html_urls.eml")
    result = parser.parse()

    extracted_urls = [u.url for u in result.urls]
    assert "https://tracker.analytics.com/pixel.png" in extracted_urls
    assert "http://phish-login.com/submit.php" in extracted_urls
    assert "https://legit-cdn.org/styles.css" in extracted_urls


def test_email_without_received_headers():
    raw = (
        b"From: user@direct.com\n"
        b"To: receiver@direct.com\n"
        b"Subject: Direct Draft without Received Headers\n"
        b"\n"
        b"Direct local submission."
    )
    parser = EmailForensicParser(raw_bytes=raw, filename="no_received.eml")
    result = parser.parse()

    assert result.relay_chain.total_hops == 0
    assert result.relay_chain.origin_ip is None
    assert "Relay path unavailable" in result.relay_chain.relay_availability_status


def test_email_without_authentication_headers():
    raw = (
        b"From: unverified@old-server.org\n"
        b"To: target@corp.com\n"
        b"Subject: Internal Note\n"
        b"\n"
        b"No auth headers recorded on legacy gateway."
    )
    parser = EmailForensicParser(raw_bytes=raw, filename="no_auth.eml")
    result = parser.parse()

    assert result.authentication.spf_result == "none"
    assert result.authentication.dkim_result == "none"
    assert result.authentication.dmarc_result == "none"
    assert result.authentication.availability_status == "Not available in supplied evidence"


def test_malformed_email_resilience():
    # Truncated MIME multipart with broken boundary
    raw = (
        b"Content-Type: multipart/mixed; boundary=\"BROKEN_BOUNDARY\"\n"
        b"Subject: Corrupted Packet\n"
        b"\n"
        b"--BROKEN_BOUNDARY\n"
        b"Content-Type: text/plain\n"
        b"\n"
        b"Incomplete payload that ends abruptly\n"
    )
    parser = EmailForensicParser(raw_bytes=raw, filename="corrupted.eml")
    result = parser.parse()

    assert result.success is True
    assert result.body.has_plain_text is True


def test_large_email_within_limit():
    large_body = "A" * (200 * 1024)  # 200KB text
    raw = (
        f"From: large@benchmark.com\n"
        f"To: test@benchmark.com\n"
        f"Subject: Large Valid Email Benchmark\n"
        f"\n"
        f"{large_body}"
    ).encode("utf-8")

    parser = EmailForensicParser(raw_bytes=raw, filename="large_email.eml")
    result = parser.parse()

    assert result.success is True
    assert result.file_size_bytes == len(raw)
    assert len(result.body.text_plain) == len(large_body)

def test_malformed_structured_header_uses_compatibility_parser():
    # The default email policy may defer parsing this malformed Message-ID
    # until header access. The parser should fall back instead of crashing.
    raw = (
        b"From: sender@example.test\n"
        b"To: analyst@example.test\n"
        b"Message-ID: <@example.test>\n"
        b"Subject: malformed header regression\n"
        b"\n"
        b"Please review this message.\n"
    )

    result = EmailForensicParser(raw_bytes=raw, filename="malformed_header.eml").parse()

    assert result.success is True
    assert result.evidence_hashes.sha256
    assert result.metadata.from_sender.address == "sender@example.test"
