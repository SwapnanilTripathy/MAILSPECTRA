from typing import Optional
import httpx

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.intelligence.schemas import EvidenceSource, RDAPDomainInfo


OFFLINE_RDAP_FIXTURES = {
    "legitcorp.com": {
        "registrar": "Corporation Service Company (CSC)",
        "creation_date": "2015-03-12T00:00:00Z",
        "expiration_date": "2028-03-12T00:00:00Z",
        "updated_date": "2025-02-10T00:00:00Z",
        "nameservers": ["ns1.legitcorp.com", "ns2.legitcorp.com"],
        "domain_status": ["clientTransferProhibited", "serverUpdateProhibited"],
        "privacy_protected": False,
    },
    "global-banking-corp.com": {
        "registrar": "NameCheap Inc.",
        "creation_date": "2026-08-20T11:45:00Z",
        "expiration_date": "2027-08-20T11:45:00Z",
        "updated_date": "2026-08-20T11:45:00Z",
        "nameservers": ["ns1.attacker-dns.top"],
        "domain_status": ["active"],
        "privacy_protected": True,
    },
}


class RDAPClientService:
    """Performs non-intrusive Registration Data Access Protocol (RDAP) domain lookups."""

    def __init__(self, mode: Optional[str] = None):
        self.mode = mode or settings.INTELLIGENCE_MODE.lower()
        self.timeout = settings.HTTP_INTEL_TIMEOUT_SECONDS

    async def lookup_domain(self, domain_str: str) -> RDAPDomainInfo:
        clean_domain = domain_str.strip().lower().rstrip(".")
        if not clean_domain or "." not in clean_domain:
            return RDAPDomainInfo(
                domain=clean_domain,
                lookup_status="INVALID_DOMAIN",
                source=EvidenceSource.RDAP.value,
            )

        if self.mode == "offline":
            return self._lookup_offline(clean_domain)

        return await self._lookup_live(clean_domain)

    def _lookup_offline(self, domain: str) -> RDAPDomainInfo:
        if domain in OFFLINE_RDAP_FIXTURES:
            f = OFFLINE_RDAP_FIXTURES[domain]
            return RDAPDomainInfo(
                domain=domain,
                registrar=f.get("registrar"),
                creation_date=f.get("creation_date"),
                expiration_date=f.get("expiration_date"),
                updated_date=f.get("updated_date"),
                nameservers=f.get("nameservers", []),
                domain_status=f.get("domain_status", []),
                privacy_protected=f.get("privacy_protected", False),
                raw_rdap_url=f"https://rdap.org/domain/{domain}",
                lookup_status="FIXTURE",
                source=EvidenceSource.OFFLINE_FIXTURE.value,
            )

        return RDAPDomainInfo(
            domain=domain,
            raw_rdap_url=f"https://rdap.org/domain/{domain}",
            lookup_status="UNAVAILABLE",
            source=EvidenceSource.OFFLINE_FIXTURE.value,
        )

    async def _lookup_live(self, domain: str) -> RDAPDomainInfo:
        url = f"https://rdap.org/domain/{domain}"
        try:
            from backend.app.intelligence.http_client import provider_json
            code, data = await provider_json(url, {"Accept":"application/rdap+json"})
            if code == 200:
                    
                # Extract registrar
                registrar = None
                for entity in data.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break

                # Extract events (creation, expiration, updated)
                creation_date = None
                expiration_date = None
                updated_date = None
                for event in data.get("events", []):
                    action = event.get("eventAction")
                    date_str = event.get("eventDate")
                    if action == "registration":
                        creation_date = date_str
                    elif action == "expiration":
                        expiration_date = date_str
                    elif action == "last changed" or action == "last update":
                        updated_date = date_str

                # Extract nameservers
                nameservers = []
                for ns in data.get("nameservers", []):
                    ns_name = ns.get("ldhName")
                    if ns_name:
                        nameservers.append(ns_name.lower())

                # Privacy protection check
                raw_text = str(data).lower()
                privacy_protected = "privacy" in raw_text or "whoisguard" in raw_text or "withheld" in raw_text or "redacted" in raw_text

                return RDAPDomainInfo(
                    domain=domain,
                    registrar=registrar,
                    creation_date=creation_date,
                    expiration_date=expiration_date,
                    updated_date=updated_date,
                    nameservers=nameservers,
                    domain_status=data.get("status", []),
                    privacy_protected=privacy_protected,
                    raw_rdap_url=url,
                    lookup_status="SUCCESS",
                    source=EvidenceSource.RDAP.value,
                )
            elif code == 404:
                return RDAPDomainInfo(domain=domain, lookup_status="NOT_FOUND", raw_rdap_url=url)
            elif code == 429:
                return RDAPDomainInfo(domain=domain, lookup_status="RATE_LIMITED", raw_rdap_url=url)
            else:
                return RDAPDomainInfo(domain=domain, lookup_status=f"HTTP_{code}", raw_rdap_url=url)
        except Exception as e:
            logger.warning("RDAP failed: %s", type(e).__name__)
            return RDAPDomainInfo(domain=domain, lookup_status="ERROR", raw_rdap_url=url)
