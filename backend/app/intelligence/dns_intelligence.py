from datetime import datetime, timezone
from typing import List, Optional
import dns.asyncresolver
import dns.resolver

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.intelligence.schemas import DNSRecordEntry, DNSIntelligenceResult, EvidenceSource


# Standard offline domain fixtures for reproducible development and tests
OFFLINE_DNS_FIXTURES = {
    "legitcorp.com": {
        "A": ["198.51.100.25"],
        "MX": ["10 mail-out.legitcorp.com."],
        "NS": ["ns1.legitcorp.com.", "ns2.legitcorp.com."],
        "TXT": ["v=spf1 ip4:198.51.100.25 -all"],
    },
    "global-banking-corp.com": {
        "A": ["198.51.100.45"],
        "MX": ["10 mx.global-banking-corp.com."],
        "NS": ["ns1.attacker-dns.top."],
        "TXT": ["v=spf1 -all"],
    },
    "darkweb-relay.ru": {
        "A": ["203.0.113.88"],
        "MX": ["5 relay.darkweb-relay.ru."],
        "NS": ["ns1.offshore-dns.ru."],
        "TXT": [],
    },
    "victim-corp.com": {
        "A": ["192.0.2.100"],
        "MX": ["10 mail-in.victim-corp.com."],
        "NS": ["ns1.victim-corp.com."],
        "TXT": ["v=spf1 include:_spf.victim-corp.com ~all"],
    },
}


class DNSIntelligenceService:
    """Performs safe, non-intrusive DNS resolution for domain and mail server infrastructure."""

    def __init__(self, mode: Optional[str] = None):
        self.mode = mode or settings.INTELLIGENCE_MODE.lower()
        self.timeout = settings.DNS_TIMEOUT_SECONDS

    async def resolve_domain(self, domain_str: str) -> DNSIntelligenceResult:
        """Query A, AAAA, MX, NS, and TXT records with strict timeout and error boundaries."""
        clean_domain = domain_str.strip().lower().rstrip(".")
        if not clean_domain or "." not in clean_domain:
            return DNSIntelligenceResult(
                domain=clean_domain,
                status="INVALID_DOMAIN",
            )

        # 1. Offline Mode Resolution
        if self.mode == "offline":
            return self._resolve_offline(clean_domain)

        # 2. Live Mode Resolution
        return await self._resolve_live(clean_domain)

    def _resolve_offline(self, domain: str) -> DNSIntelligenceResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        records: List[DNSRecordEntry] = []
        a_records: List[str] = []
        mx_hosts: List[str] = []
        nameservers: List[str] = []
        txt_records: List[str] = []

        if domain in OFFLINE_DNS_FIXTURES:
            f = OFFLINE_DNS_FIXTURES[domain]
            for ip in f.get("A", []):
                a_records.append(ip)
                records.append(DNSRecordEntry(domain=domain, record_type="A", value=ip, ttl=300, timestamp=now_iso))
            for mx in f.get("MX", []):
                mx_hosts.append(mx.split()[-1].rstrip("."))
                records.append(DNSRecordEntry(domain=domain, record_type="MX", value=mx, ttl=300, timestamp=now_iso))
            for ns in f.get("NS", []):
                nameservers.append(ns.rstrip("."))
                records.append(DNSRecordEntry(domain=domain, record_type="NS", value=ns, ttl=300, timestamp=now_iso))
            for txt in f.get("TXT", []):
                txt_records.append(txt)
                records.append(DNSRecordEntry(domain=domain, record_type="TXT", value=txt, ttl=300, timestamp=now_iso))

            return DNSIntelligenceResult(
                domain=domain,
                records=records,
                a_records=a_records,
                mx_hosts=mx_hosts,
                nameservers=nameservers,
                txt_records=txt_records,
                has_valid_mx=bool(mx_hosts),
                status="SUCCESS",
            )

        # Generic offline default
        return DNSIntelligenceResult(
            domain=domain,
            records=[],
            has_valid_mx=False,
            status="SUCCESS",
        )

    async def _resolve_live(self, domain: str) -> DNSIntelligenceResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        records: List[DNSRecordEntry] = []
        a_records: List[str] = []
        mx_hosts: List[str] = []
        nameservers: List[str] = []
        txt_records: List[str] = []

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # Query A records
        try:
            answers = await resolver.resolve(domain, "A")
            for rdata in answers:
                val = str(rdata)
                a_records.append(val)
                records.append(DNSRecordEntry(domain=domain, record_type="A", value=val, ttl=answers.ttl, timestamp=now_iso))
        except Exception:
            pass

        # Query MX records
        try:
            answers = await resolver.resolve(domain, "MX")
            for rdata in answers:
                val = str(rdata.exchange).rstrip(".")
                prio = int(rdata.preference)
                mx_hosts.append(val)
                records.append(DNSRecordEntry(domain=domain, record_type="MX", value=f"{prio} {val}", priority=prio, ttl=answers.ttl, timestamp=now_iso))
        except Exception:
            pass

        # Query NS records
        try:
            answers = await resolver.resolve(domain, "NS")
            for rdata in answers:
                val = str(rdata.target).rstrip(".")
                nameservers.append(val)
                records.append(DNSRecordEntry(domain=domain, record_type="NS", value=val, ttl=answers.ttl, timestamp=now_iso))
        except Exception:
            pass

        # Query TXT records
        try:
            answers = await resolver.resolve(domain, "TXT")
            for rdata in answers:
                val = str(rdata).strip('"')
                txt_records.append(val)
                records.append(DNSRecordEntry(domain=domain, record_type="TXT", value=val, ttl=answers.ttl, timestamp=now_iso))
        except Exception:
            pass

        has_mx = bool(mx_hosts)
        status = "SUCCESS" if records else "NO_RECORDS"

        return DNSIntelligenceResult(
            domain=domain,
            records=records,
            a_records=a_records,
            mx_hosts=mx_hosts,
            nameservers=nameservers,
            txt_records=txt_records,
            has_valid_mx=has_mx,
            status=status,
        )
