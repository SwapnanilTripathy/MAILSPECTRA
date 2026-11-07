from email import policy
from email.parser import BytesParser
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import re


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIRECTORY = REPOSITORY_ROOT / "frontend" / "public" / "demo-samples"
DEMO_FILES = (
    "benign_newsletter.eml",
    "credential_harvest.eml",
    "executive_payment_request.eml",
)
DOCUMENTATION_NETWORKS = (
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
)


def test_bundled_demo_emails_parse_without_mime_defects():
    for filename in DEMO_FILES:
        raw = (DEMO_DIRECTORY / filename).read_bytes()
        message = BytesParser(policy=policy.default).parsebytes(raw)

        assert not message.defects, f"{filename} has parser defects: {message.defects}"
        assert message.get("From")
        assert message.get("To")
        assert message.get("Subject")
        assert message.get("Date")
        assert message.get("Message-ID")


def test_demo_emails_use_only_reserved_test_domains_and_documentation_ips():
    for filename in DEMO_FILES:
        raw = (DEMO_DIRECTORY / filename).read_text(encoding="utf-8")
        assert ".test" in raw.lower()

        for literal in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw):
            address = IPv4Address(literal)
            assert any(address in network for network in DOCUMENTATION_NETWORKS), (
                f"{filename} contains a non-documentation IP literal: {literal}"
            )


def test_demo_attachments_are_plain_text_only():
    message = BytesParser(policy=policy.default).parsebytes(
        (DEMO_DIRECTORY / "executive_payment_request.eml").read_bytes()
    )
    attachments = list(message.iter_attachments())

    assert len(attachments) == 1
    assert attachments[0].get_content_type() == "text/plain"
    assert attachments[0].get_filename() == "synthetic_invoice_notes.txt"
