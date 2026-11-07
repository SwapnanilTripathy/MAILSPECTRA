from __future__ import annotations
import math
import re
from typing import TYPE_CHECKING, Dict, List, Optional, Set
import tldextract
_TLD = tldextract.TLDExtract(suffix_list_urls=())

from backend.app.core.config import settings
from backend.app.intelligence.dns_intelligence import DNSIntelligenceService
from backend.app.intelligence.rdap import RDAPClientService
from backend.app.intelligence.schemas import DomainIntelligenceResult

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse


SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "buzz",
    "bid", "icu", "cam", "fit", "rest", "surf", "monster", "cfd", "ru", "biz"
}

POPULAR_TARGET_BRANDS = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix", "bankofamerica",
    "wellsfargo", "chase", "citibank", "outlook", "office365", "docusign", "dropbox"
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


class DomainIntelligenceService:
    """Analyzes domains across sender, Return-Path, and URLs for lexical risks, DNS, and RDAP metadata."""

    def __init__(
        self,
        dns_service: Optional[DNSIntelligenceService] = None,
        rdap_service: Optional[RDAPClientService] = None,
    ):
        self.dns_service = dns_service or DNSIntelligenceService()
        self.rdap_service = rdap_service or RDAPClientService()

    def analyze_lexical_domain(self, domain_str: str) -> DomainIntelligenceResult:
        """Perform static lexical inspection: entropy, punycode, lookalikes, and TLD risks."""
        clean_domain = domain_str.strip().lower().rstrip(".")
        ext = _TLD(clean_domain)
        reg_domain = ext.registered_domain or clean_domain
        subdomain = ext.subdomain
        tld = ext.suffix

        signals: List[str] = []

        # 1. Punycode check
        is_puny = clean_domain.startswith("xn--") or ".xn--" in clean_domain
        if is_puny:
            signals.append("IDN_PUNYCODE_DETECTED")

        # 2. Suspicious TLD check
        is_susp_tld = tld in SUSPICIOUS_TLDS
        if is_susp_tld:
            signals.append(f"HIGH_RISK_TLD (.{tld})")

        # 3. Entropy check
        entropy = round(calculate_entropy(ext.domain), 2)
        if entropy >= 3.8 and len(ext.domain) >= 10:
            signals.append("HIGH_LEXICAL_ENTROPY (not proof of DGA)")

        # 4. Excessive Subdomains check
        sub_count = len(subdomain.split(".")) if subdomain else 0
        if sub_count >= 3:
            signals.append(f"EXCESSIVE_SUBDOMAIN_DEPTH ({sub_count} levels)")

        # 5. Lookalike / Typosquatting Brand impersonation
        is_lookalike = False
        domain_core = ext.domain.replace("-", "").replace(".", "").lower()

        # Leetspeak normalization map
        leetspeak_map = str.maketrans({
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "8": "b",
            "@": "a",
        })
        normalized_domain = domain_core.translate(leetspeak_map).replace("vv", "w")

        for brand in POPULAR_TARGET_BRANDS:
            # Direct brand embedding or Leetspeak substitution
            if brand in normalized_domain:
                is_lookalike = True
                signals.append(f"BRAND_IMPERSONATION_SIGNAL (targets '{brand}')")
                break


        return DomainIntelligenceResult(
            domain=clean_domain,
            registered_domain=reg_domain,
            tld=tld,
            subdomain=subdomain,
            is_punycode=is_puny,
            is_lookalike=is_lookalike,
            entropy=entropy,
            suspicious_tld_flag=is_susp_tld,
            risk_signals=signals,
        )

    async def enrich_domains(self, analysis: EmailAnalysisResponse) -> Dict[str, DomainIntelligenceResult]:
        """Extract all candidate domains and enrich with lexical, DNS, and RDAP intelligence."""
        candidate_domains: Set[str] = set()

        if analysis.metadata.from_sender.domain:
            candidate_domains.add(analysis.metadata.from_sender.domain.lower())

        if analysis.metadata.return_path and "@" in analysis.metadata.return_path:
            rp_domain = analysis.metadata.return_path.split("@")[-1].lower()
            candidate_domains.add(rp_domain)

        for u in analysis.urls:
            if u.registered_domain:
                candidate_domains.add(u.registered_domain.lower())
            elif u.host and not u.is_ip_host:
                candidate_domains.add(u.host.lower())

        results: Dict[str, DomainIntelligenceResult] = {}

        for dom in candidate_domains:
            if not dom or "." not in dom:
                continue
            dom_result = self.analyze_lexical_domain(dom)

            # Query DNS
            dns_res = await self.dns_service.resolve_domain(dom)
            dom_result.dns = dns_res

            # Query RDAP
            rdap_res = await self.rdap_service.lookup_domain(dom)
            dom_result.rdap = rdap_res

            results[dom] = dom_result

        return results
