from __future__ import annotations
from datetime import datetime, timezone
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.logging import logger
from backend.app.database.session import AsyncSessionLocal
from backend.app.graph.campaign_correlator import CampaignCorrelator
from backend.app.graph.schemas import (
    AttributionSupportResult,
    CampaignCorrelationMatch,
    CampaignEntity,
)
from backend.app.models.entities import CampaignRecord, CaseRecord, ObservableRecord

if TYPE_CHECKING:
    from backend.app.intelligence.schemas import InfrastructureIntelligence
    from backend.app.schemas.analysis import EmailAnalysisResponse



class CorrelationPersistenceService:
    """Manages cross-email correlation against database cases and persists observables and campaigns."""

    @classmethod
    async def correlate_and_persist(
        cls,
        analysis: EmailAnalysisResponse,
        intel: Optional[InfrastructureIntelligence] = None,
        session: Optional[AsyncSession] = None,
    ) -> Tuple[List[CampaignCorrelationMatch], Optional[CampaignEntity], AttributionSupportResult]:
        """Correlate new analysis against existing cases in database and persist state."""
        close_session = False
        if session is None:
            session = AsyncSessionLocal()
            close_session = True

        try:
            # 1. Fetch historical cases and their observables
            historical_cases: List[Dict[str, Any]] = []
            try:
                stmt = select(CaseRecord).options(selectinload(CaseRecord.observables)).order_by(CaseRecord.created_at.desc()).limit(100)
                result = await session.execute(stmt)
                cases_orm = result.scalars().all()

                for c in cases_orm:
                    case_dict: Dict[str, Any] = {
                        "case_id": c.case_id,
                        "filename": c.filename,
                        "subject": c.subject,
                        "from_address": c.from_address,
                        "sender_domain": c.sender_domain,
                        "classification": c.classification,
                        "risk_score": c.risk_score,
                        "ips": [],
                        "domains": [],
                        "urls": [],
                    }
                    for obs in c.observables:
                        if obs.observable_type == "IP":
                            case_dict["ips"].append(obs.value)
                        elif obs.observable_type == "DOMAIN":
                            case_dict["domains"].append(obs.value)
                        elif obs.observable_type == "URL":
                            case_dict["urls"].append(obs.value)

                    historical_cases.append(case_dict)
            except Exception as e:
                raise

            # 2. Run Campaign Correlator
            matches, campaign_entity, attribution = CampaignCorrelator.correlate_case(
                analysis=analysis,
                historical_cases=historical_cases,
                intel=intel,
            )

            # Store the complete analysis before any presentation masking is applied.
            analysis.campaign_correlations = matches
            analysis.active_campaign = campaign_entity
            analysis.attribution_support = attribution

            # 3. Persist current CaseRecord and Observables
            try:
                origin_ip = None
                if intel and intel.origin_assessment:
                    origin_ip = intel.origin_assessment.earliest_reliable_ip

                case_rec = CaseRecord(
                    case_id=analysis.case_id,
                    filename=analysis.filename,
                    subject=analysis.metadata.subject or "",
                    from_address=analysis.metadata.from_sender.address.lower(),
                    sender_domain=analysis.metadata.from_sender.domain.lower(),
                    origin_ip=origin_ip,
                    classification=analysis.threat_assessment.classification,
                    risk_score=analysis.threat_assessment.risk_score,
                    confidence=analysis.threat_assessment.confidence,
                    sha256=analysis.evidence_hashes.sha256,
                    full_analysis_json=analysis.model_dump_json(),
                )
                session.add(case_rec)

                # Add IP observables
                for ip_item in analysis.ips:
                    session.add(
                        ObservableRecord(
                            case_id=analysis.case_id,
                            observable_type="IP",
                            value=ip_item.ip,
                            defanged_value=ip_item.defanged_ip,
                            source=ip_item.source,
                        )
                    )

                # Add Domain observables
                if analysis.metadata.from_sender.domain:
                    session.add(
                        ObservableRecord(
                            case_id=analysis.case_id,
                            observable_type="DOMAIN",
                            value=analysis.metadata.from_sender.domain.lower(),
                            defanged_value=analysis.metadata.from_sender.domain.lower(),
                            source="EMAIL_HEADER",
                        )
                    )

                # Add URL observables
                for url_item in analysis.urls:
                    session.add(
                        ObservableRecord(
                            case_id=analysis.case_id,
                            observable_type="URL",
                            value=url_item.url,
                            defanged_value=url_item.defanged_url,
                            source=url_item.source,
                        )
                    )
                    if url_item.registered_domain:
                        session.add(
                            ObservableRecord(
                                case_id=analysis.case_id,
                                observable_type="DOMAIN",
                                value=url_item.registered_domain.lower(),
                                defanged_value=url_item.registered_domain.lower(),
                                source="URL_EXTRACTION",
                            )
                        )

                # 4. Persist CampaignRecord if created
                if campaign_entity:
                    camp_stmt = select(CampaignRecord).where(CampaignRecord.campaign_id == campaign_entity.campaign_id)
                    existing_camp = (await session.execute(camp_stmt)).scalar_one_or_none()

                    if existing_camp:
                        existing_camp.member_case_ids_json = json.dumps(campaign_entity.member_case_ids)
                        existing_camp.shared_indicators_json = json.dumps(campaign_entity.shared_infrastructure)
                        existing_camp.confidence = campaign_entity.confidence
                        existing_camp.last_seen = datetime.now(timezone.utc)
                    else:
                        session.add(
                            CampaignRecord(
                                campaign_id=campaign_entity.campaign_id,
                                name=campaign_entity.name,
                                primary_threat_type=campaign_entity.primary_threat_type,
                                confidence=campaign_entity.confidence,
                                member_case_ids_json=json.dumps(campaign_entity.member_case_ids),
                                shared_indicators_json=json.dumps(campaign_entity.shared_infrastructure),
                            )
                        )

                await session.flush()
                if close_session:
                    await session.commit()
            except Exception as e:
                await session.rollback()
                raise

            return matches, campaign_entity, attribution

        finally:
            if close_session and session:
                await session.close()
