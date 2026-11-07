from __future__ import annotations
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Set
from backend.app.intelligence.geoip import get_geoip_provider
from backend.app.intelligence.schemas import GeoLocationInfo, OriginAssessmentResult
from backend.app.utils.crypto import defang_ip
from backend.app.utils.network import classify_ip, is_valid_ip

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse



class IPIntelligenceService:
    """Performs IP geolocation enrichment and chronological relay path origin assessment."""

    def __init__(self, geo_provider=None):
        self.geo_provider = geo_provider or get_geoip_provider()

    async def enrich_ips(self, analysis: EmailAnalysisResponse) -> Dict[str, GeoLocationInfo]:
        """Perform geolocation and ASN enrichment on all distinct extracted IPs."""
        results: Dict[str, GeoLocationInfo] = {}
        seen_ips: Set[str] = set()

        # Collect IPs from observables and relay chain
        candidate_ips: List[str] = []
        for ext_ip in analysis.ips:
            candidate_ips.append(ext_ip.ip)
        for hop in analysis.relay_chain.hops:
            if hop.from_ip:
                candidate_ips.append(hop.from_ip)

        for raw_ip in candidate_ips:
            clean = raw_ip.strip("[].,; ")
            if not clean or clean in seen_ips or not is_valid_ip(clean):
                continue
            seen_ips.add(clean)
            geo_info = await self.geo_provider.lookup(clean)
            results[clean] = geo_info

        return results

    @classmethod
    def assess_origin(
        cls,
        analysis: EmailAnalysisResponse,
        ip_intel_map: Optional[Dict[str, GeoLocationInfo]] = None,
    ) -> OriginAssessmentResult:
        """Evaluate chronological Received hops to determine the earliest reliable observable source IP."""
        hops = analysis.relay_chain.hops
        evidentiary_basis: List[str] = []
        limitations: List[str] = []

        if not hops:
            return OriginAssessmentResult(
                earliest_reliable_ip=None,
                confidence=0.0,
                evidentiary_basis=["Relay path unavailable — no usable Received headers were present in the supplied artifact."],
                limitations=["Transmission path cannot be reconstructed without Received headers."],
            )


        # Received headers in RelayChainSummary are sorted in chronological order (hop 1 = earliest MTA)
        first_hop = hops[0]
        first_ip = first_hop.from_ip
        first_host = first_hop.from_host

        earliest_reliable_ip = None
        probable_host = first_host
        is_internal = False
        confidence = 0.50

        # Case 1: First hop has a valid public IP
        first_ip_class = classify_ip(first_ip) if first_ip else {}
        if first_ip and first_ip_class.get("is_public", False):
            earliest_reliable_ip = first_ip
            confidence = 0.85
            evidentiary_basis.append(
                f"Hop 1 (earliest MTA) recorded public IP '{first_ip}' from host '{first_host or 'unknown'}'."
            )

        # Case 2: First hop is internal/private (e.g. 10.x, 192.168.x, 127.0.0.1)
        elif first_ip and first_ip_class.get("is_private", False):
            is_internal = True
            evidentiary_basis.append(
                f"Hop 1 originated from an internal private network IP ({first_ip}) behind corporate gateway."
            )
            # Find first subsequent public hop in the chain
            for hop in hops[1:]:
                hop_class = classify_ip(hop.from_ip) if hop.from_ip else {}
                if hop.from_ip and hop_class.get("is_public", False):
                    earliest_reliable_ip = hop.from_ip
                    probable_host = hop.from_host or probable_host
                    confidence = 0.75
                    evidentiary_basis.append(
                        f"Earliest public exit gateway identified at Hop {hop.hop_index} ({hop.from_ip})."
                    )
                    break

            if not earliest_reliable_ip:
                earliest_reliable_ip = first_ip
                confidence = 0.60
                limitations.append("All observed relay hops reside within private/internal address space.")

        # Case 3: No IP in first hop, scan for earliest public hop
        else:
            for hop in hops:
                hop_class = classify_ip(hop.from_ip) if hop.from_ip else {}
                if hop.from_ip and hop_class.get("is_public", False):
                    earliest_reliable_ip = hop.from_ip
                    probable_host = hop.from_host
                    confidence = 0.70
                    evidentiary_basis.append(
                        f"First public IP observable resolved at Hop {hop.hop_index} ({hop.from_ip})."
                    )
                    break

        # Uploaded headers do not establish a trusted receiving boundary.
        confidence = 0.0
        limitations.append("Supplied Received headers are untrusted. Confidence is unavailable without trusted acquisition; any configured receiver match is an assumption.")
        # Attach Geo/ASN context if available
        if ip_intel_map and earliest_reliable_ip in ip_intel_map:
            geo = ip_intel_map[earliest_reliable_ip]
            if geo.country and geo.asn and geo.source != "OFFLINE_FIXTURE":
                evidentiary_basis.append(
                    f"Probable originating infrastructure geolocates to {geo.city or geo.region or geo.country} ({geo.country}) under ASN {geo.asn} ({geo.isp or geo.organization})."
                )

        limitations.append(
            "Origin assessment represents the earliest reliable network hop observable in headers. It indicates infrastructure location, not necessarily the physical location of the human actor."
        )

        return OriginAssessmentResult(
            earliest_reliable_ip=earliest_reliable_ip,
            defanged_earliest_reliable_ip=defang_ip(earliest_reliable_ip) if earliest_reliable_ip else None,
            probable_origin_host=probable_host,
            confidence=round(confidence, 2),
            is_internal_hop=is_internal,
            evidentiary_basis=evidentiary_basis,
            limitations=limitations,
        )
