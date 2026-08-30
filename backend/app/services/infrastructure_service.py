from __future__ import annotations
from typing import TYPE_CHECKING, Optional

from backend.app.core.config import settings
from backend.app.intelligence.domain_intelligence import DomainIntelligenceService
from backend.app.intelligence.ip_intelligence import IPIntelligenceService
from backend.app.intelligence.reputation import ThreatReputationService
from backend.app.intelligence.schemas import InfrastructureIntelligence

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse



class InfrastructureIntelligenceService:
    """Coordinates IP geolocation, DNS, RDAP, threat reputation, and origin assessment."""

    def __init__(
        self,
        ip_service: Optional[IPIntelligenceService] = None,
        domain_service: Optional[DomainIntelligenceService] = None,
        reputation_service: Optional[ThreatReputationService] = None,
    ):
        self.ip_service = ip_service or IPIntelligenceService()
        self.domain_service = domain_service or DomainIntelligenceService()
        self.reputation_service = reputation_service or ThreatReputationService()
        self.mode = settings.INTELLIGENCE_MODE.lower()

    async def gather_intelligence(self, analysis: EmailAnalysisResponse) -> InfrastructureIntelligence:
        """Enrich email observables with IP geolocation, DNS, RDAP, and reputation data."""
        # 1. IP Geolocation & ASN Enrichment
        ip_intel = await self.ip_service.enrich_ips(analysis)

        # 2. Origin Assessment (Chronological Received Header evaluation)
        origin_assessment = self.ip_service.assess_origin(analysis, ip_intel)

        # 3. Domain Intelligence (DNS + RDAP + Lexical)
        domain_intel = await self.domain_service.enrich_domains(analysis)

        # 4. Threat Reputation Lookups
        reputation_intel = await self.reputation_service.enrich_observables(analysis)

        return InfrastructureIntelligence(
            mode=self.mode,
            ip_intelligence=ip_intel,
            domain_intelligence=domain_intel,
            reputation_intelligence=reputation_intel,
            origin_assessment=origin_assessment,
        )
