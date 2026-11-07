from email import policy
from email.parser import BytesParser
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import re

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIRECTORY = REPOSITORY_ROOT / "frontend" / "public" / "demo-samples"
DEMO_FILES = (
    "benign_newsletter.eml",
    "credential_harvest.eml",
    "executive_payment_request.eml",
)
EMAIL_HOST_PATTERN = re.compile(r"@([a-z0-9.-]+\.[a-z]{2,63})", re.IGNORECASE)
URL_HOST_PATTERN = re.compile(
    r"https?://([a-z0-9.-]+\.[a-z]{2,63})(?=[:/?#\s]|$)",
    re.IGNORECASE,
)
RECEIVED_HOST_PATTERN = re.compile(
    r"\b(?:from|by)\s+([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)*\.[a-z]{2,63})\b",
    re.IGNORECASE,
)


def extract_hostnames(raw: str) -> set[str]:
    """Extract hostnames from email addresses, URLs, and Received relay fields."""
    hosts = (
        EMAIL_HOST_PATTERN.findall(raw)
        + URL_HOST_PATTERN.findall(raw)
        + RECEIVED_HOST_PATTERN.findall(raw)
    )
    return {hostname.lower() for hostname in hosts}


def assert_reserved_hostnames(raw: str) -> None:
    """Require all extracted hostnames to use the reserved .test namespace."""
    hostnames = extract_hostnames(raw)
    assert hostnames, "sample should contain at least one hostname"
    for hostname in hostnames:
        assert hostname.lower().endswith(".test"), (
            f"hostname {hostname} must use the reserved .test namespace"
        )

DOCUMENTATION_NETWORKS = (
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
)


def test_hostname_extraction_detects_non_reserved_domains_in_supported_contexts():
    """Ensure the extractor finds non-reserved hosts so fixture checks reject them."""
    raw = (
        "From: sender@outside.example.org\n"
        "Received: from relay.example.test by mx.example.test\n"
        "Open https://links.example.net/path\n"
    )
    assert extract_hostnames(raw) == {
        "outside.example.org",
        "relay.example.test",
        "mx.example.test",
        "links.example.net",
    }
    with pytest.raises(AssertionError, match=r"hostname outside\\.example\\.org must use"):
        assert_reserved_hostnames(raw)


def test_bundled_demo_emails_parse_without_mime_defects():
    """Ensure each bundled scenario parses as a well-formed RFC 5322/MIME message."""
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
    """Require every hostname and IPv4 literal to use reserved demonstration ranges."""
    for filename in DEMO_FILES:
        raw = (DEMO_DIRECTORY / filename).read_text(encoding="utf-8")
        assert_reserved_hostnames(raw)

        for literal in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw):
            address = IPv4Address(literal)
            assert any(address in network for network in DOCUMENTATION_NETWORKS), (
                f"{filename} contains a non-documentation IP literal: {literal}"
            )


def test_demo_attachments_are_plain_text_only():
    """Keep the demonstration attachment inert and restricted to plain text."""
    message = BytesParser(policy=policy.default).parsebytes(
        (DEMO_DIRECTORY / "executive_payment_request.eml").read_bytes()
    )
    attachments = list(message.iter_attachments())

    assert len(attachments) == 1
    assert attachments[0].get_content_type() == "text/plain"
    assert attachments[0].get_filename() == "synthetic_invoice_notes.txt"
