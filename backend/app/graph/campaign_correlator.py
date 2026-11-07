from __future__ import annotations
import hashlib
from backend.app.core.config import settings
from backend.app.utils.network import classify_ip
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from backend.app.graph.schemas import (
    AttributionSupportResult,
    CampaignCorrelationMatch,
    CampaignEntity,
)
from backend.app.models.entities import CaseRecord, ObservableRecord

if TYPE_CHECKING:
    from backend.app.intelligence.schemas import InfrastructureIntelligence
    from backend.app.schemas.analysis import EmailAnalysisResponse



class CampaignCorrelator:
    """Performs cross-case observable correlation, campaign clustering, and attribution support analysis."""

    @classmethod
    def correlate_case(
        cls,
        analysis: EmailAnalysisResponse,
        historical_cases: List[Dict[str, Any]],
        intel: Optional[InfrastructureIntelligence] = None,
    ) -> Tuple[List[CampaignCorrelationMatch], Optional[CampaignEntity], AttributionSupportResult]:
        """Correlate newly analyzed email against historical cases to discover shared campaigns and attribution evidence."""
        matches: List[CampaignCorrelationMatch] = []
        current_case_id = analysis.case_id

        # 1. Extract current observables for comparison
        curr_ips: Set[str] = {ip.ip for ip in analysis.ips if ip.is_public}
        for hop in analysis.relay_chain.hops:
            if hop.from_ip and classify_ip(hop.from_ip).get("is_public"):
                curr_ips.add(hop.from_ip)
        for u in analysis.urls:
            if u.is_ip_host and u.host and classify_ip(u.host).get("is_public"):
                curr_ips.add(u.host)

        curr_domains: Set[str] = set()
        if analysis.metadata.from_sender.domain:
            curr_domains.add(analysis.metadata.from_sender.domain.lower())
        for u in analysis.urls:
            if u.registered_domain:
                curr_domains.add(u.registered_domain.lower())

        curr_urls: Set[str] = {u.url for u in analysis.urls}

        curr_sender = analysis.metadata.from_sender.address.lower()
        curr_class = analysis.threat_assessment.classification

        # 2. Iterate through historical cases
        for hist in historical_cases:
            hist_id = hist.get("case_id", "")
            if hist_id == current_case_id:
                continue

            shared_inds: List[str] = []
            evidence_lines: List[str] = []
            score = 0.0

            # Compare IP overlap
            hist_ips = set(hist.get("ips", []))
            common_ips = curr_ips.intersection(hist_ips)
            if common_ips:
                shared_inds.append("SHARED_IP_INFRASTRUCTURE")
                evidence_lines.append(f"Shared IP address(es): {', '.join(common_ips)}")
                score += 0.40

            # Compare Domain overlap
            hist_domains = set(hist.get("domains", []))
            common_domains = curr_domains.intersection(hist_domains)
            if common_domains:
                shared_inds.append("SHARED_DOMAIN_INFRASTRUCTURE")
                evidence_lines.append(f"Shared domain(s): {', '.join(common_domains)}")
                score += 0.30

            # Compare exact URL overlap
            hist_urls = set(hist.get("urls", []))
            common_urls = curr_urls.intersection(hist_urls)
            if common_urls:
                shared_inds.append("IDENTICAL_URL_PAYLOAD")
                evidence_lines.append(f"Identical target URL payload: {', '.join(common_urls)}")
                score += 0.45

            # Compare Sender address
            hist_sender = hist.get("from_address", "").lower()
            if curr_sender and hist_sender and curr_sender == hist_sender:
                shared_inds.append("REPEATED_SENDER_IDENTITY")
                evidence_lines.append(f"Exact matching sender address: '{curr_sender}'")
                score += 0.25

            # Compare Threat Category similarity
            hist_class = hist.get("classification", "")
            if curr_class != "LEGITIMATE" and curr_class == hist_class:
                shared_inds.append("MATCHING_THREAT_PATTERN")
                score += 0.10

            final_score = min(1.0, round(score, 2))
            if final_score >= settings.CORRELATION_MATCH_THRESHOLD and shared_inds:
                matches.append(
                    CampaignCorrelationMatch(
                        related_case_id=hist_id,
                        related_case_filename=hist.get("filename", ""),
                        related_case_subject=hist.get("subject", ""),
                        related_case_classification=hist_class,
                        correlation_score=final_score,
                        shared_indicators=shared_inds,
                        shared_values={"ips": sorted(common_ips), "domains":sorted(common_domains), "urls":sorted(common_urls), "senders":[curr_sender] if hist_sender == curr_sender else []},
                        evidence=evidence_lines,
                    )
                )

        # Sort matches by correlation score descending
        matches.sort(key=lambda m: m.correlation_score, reverse=True)

        # 3. Dynamic Campaign Entity Clustering
        campaign_entity: Optional[CampaignEntity] = None
        high_conf_matches = [m for m in matches if m.correlation_score >= settings.CORRELATION_CLUSTER_THRESHOLD]
        if high_conf_matches:
            member_ids = [current_case_id] + [m.related_case_id for m in high_conf_matches]
            member_ids = sorted(list(set(member_ids)))

            # Deterministic campaign ID from member set
            cid_hash = hashlib.sha256("|".join(sorted({v for m in high_conf_matches for values in m.shared_values.values() for v in values})).encode()).hexdigest()[:12].upper()
            campaign_id = f"CAMPAIGN-{cid_hash}"

            shared_infra: Dict[str, List[str]] = {
                "ips": sorted({v for match in high_conf_matches for v in match.shared_values["ips"]}),
                "domains": sorted({v for match in high_conf_matches for v in match.shared_values["domains"]}),
                "urls": sorted({v for match in high_conf_matches for v in match.shared_values["urls"]}),
            }

            campaign_entity = CampaignEntity(
                campaign_id=campaign_id,
                name=f"Correlated Threat Cluster #{cid_hash}",
                primary_threat_type=curr_class,
                confidence=round(high_conf_matches[0].correlation_score, 2),
                member_case_ids=member_ids,
                shared_infrastructure=shared_infra,
                threat_summary=(
                    f"Cluster of {len(member_ids)} correlated cases sharing infrastructure across "
                    f"{len(shared_infra['ips'])} IP(s) and {len(shared_infra['domains'])} domain(s)."
                ),
            )

        # 4. Attribution Support Assessment
        attribution_result = cls._evaluate_attribution_support(analysis, matches, campaign_entity, intel)

        return matches, campaign_entity, attribution_result

    @classmethod
    def _evaluate_attribution_support(
        cls,
        analysis: EmailAnalysisResponse,
        matches: List[CampaignCorrelationMatch],
        campaign: Optional[CampaignEntity],
        intel: Optional[InfrastructureIntelligence],
    ) -> AttributionSupportResult:
        """Evaluate evidence for technical attribution support without identifying human individuals."""
        evidence: List[str] = []
        mitigating: List[str] = []
        limitations: List[str] = [
            "Attribution support reflects technical infrastructure relationships and operational indicators.",
            "Never equates infrastructure location or domain registration with the physical identity of human perpetrators."
        ]

        auth = analysis.authentication
        from_sender = analysis.metadata.from_sender
        risk_score = analysis.threat_assessment.risk_score

        limitations.append("Reported authentication headers are untrusted; rule support is not a calibrated probability.")
        if campaign:
            assessment = "SHARED_CAMPAIGN_INFRASTRUCTURE"
            confidence = campaign.confidence
            evidence = [line for match in matches for line in match.evidence]
        elif auth.spf_result == "fail" or auth.dmarc_result == "fail":
            assessment = "POSSIBLE_IDENTITY_INCONSISTENCY"
            confidence = 0.0
            evidence = ["Supplied headers report authentication failure; independent verification is required."]
        else:
            assessment = "INSUFFICIENT_EVIDENCE"
            confidence = 0.0
            evidence = ["No verified evidence establishes sender authenticity or an actor identity."]

        return AttributionSupportResult(
            assessment=assessment,
            confidence=round(confidence, 2),
            evidentiary_basis=evidence,
            mitigating_factors=mitigating,
            limitations=limitations,
        )
