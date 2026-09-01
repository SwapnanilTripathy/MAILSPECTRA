import asyncio
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.logging import logger
from backend.app.graph.graph_builder import ThreatGraphBuilder
from backend.app.ml.explainer import ThreatExplainer
from backend.app.ml.feature_extractor import FeatureExtractor
from backend.app.ml.model_loader import ModelLoader
from backend.app.ml.predictor import ThreatPredictor
from backend.app.ml.risk_engine import ThreatRiskEngine
from backend.app.ml.schemas import FeatureExtractionSummary, ThreatClass
from backend.app.schemas.analysis import (
    EmailAnalysisResponse,
    InitialThreatAssessment,
    ThreatIndicator as LegacyThreatIndicator,
)
from backend.app.services.correlation_service import CorrelationPersistenceService
from backend.app.services.email_parser import EmailForensicParser
from backend.app.services.infrastructure_service import InfrastructureIntelligenceService


class ThreatAnalysisPipeline:
    """End-to-End Forensic Analysis, AI Threat Intelligence & Threat Graph Pipeline.

    Flow:
        .EML Raw Bytes
             ↓
        Phase 1: Forensic Email Parser (MIME, Headers, Relay, URLs, IPs, Hashes)
             ↓
        Phase 2: Feature Extraction (TF-IDF Text + 34 Engineered Security Signals)
             ↓
        Phase 2: ML Predictor (Multi-class Threat Probability Distribution)
             ↓
        Phase 2: Threat Risk Engine (Transparent 0-100 Hybrid Scoring & Observables)
             ↓
        Phase 2: SHAP Explainer (Local Linear Feature Attributions)
             ↓
        Phase 3: Infrastructure Intelligence (IP Geolocation, ASN, DNS, RDAP, Reputation)
             ↓
        Phase 3: Origin Assessment (Chronological Relay Chain Evaluation)
             ↓
        Phase 3: Real NetworkX Threat Graph Construction & Serialization
             ↓
        Phase 3: Cross-Case Campaign Correlation & DB Persistence
             ↓
        Phase 3: Attribution Support Assessment
             ↓
        Unified Structured Forensic JSON Response
    """

    def __init__(self):
        self.model_bundle = ModelLoader.load_model()
        self.predictor = ThreatPredictor(model_bundle=self.model_bundle)
        self.explainer = ThreatExplainer(model_bundle=self.model_bundle)
        self.infra_service = InfrastructureIntelligenceService()

    async def analyze_bytes_async(
        self,
        raw_bytes: bytes,
        filename: Optional[str] = "uploaded.eml",
        db_session: Optional[AsyncSession] = None,
    ) -> EmailAnalysisResponse:
        """Execute full asynchronous pipeline across Phase 1, Phase 2, and Phase 3."""
        # 1. Phase 1 Forensic Parsing
        parser = EmailForensicParser(raw_bytes=raw_bytes, filename=filename)
        base_analysis = parser.parse()

        # 2. Phase 2 Feature Extraction
        structured_features = FeatureExtractor.extract_structured_features(base_analysis)
        text_repr = FeatureExtractor.extract_text(base_analysis)

        # 3. Phase 2 ML Prediction
        prediction_result, feature_matrix = self.predictor.predict(base_analysis)

        # 4. Phase 2 Risk Engine Evaluation
        risk_result = ThreatRiskEngine.evaluate(
            analysis=base_analysis,
            prediction=prediction_result,
            structured_features=structured_features,
        )

        # 5. Phase 2 SHAP Explainability
        shap_result = self.explainer.explain(
            predicted_class=prediction_result.predicted_class,
            X=feature_matrix,
            structured_features=structured_features,
        )

        # 6. NLP & Content Intelligence Analysis
        from backend.app.analyzers.content_analyzer import ContentIntelligenceAnalyzer
        content_intelligence = ContentIntelligenceAnalyzer.analyze(
            metadata=base_analysis.metadata,
            body=base_analysis.body,
            urls=base_analysis.urls,
            attachments=base_analysis.attachments,
        )

        # 7. Feature Summary
        feature_summary = FeatureExtractionSummary(
            total_features_extracted=len(structured_features),
            text_feature_count=len(text_repr.split()),
            structured_feature_count=len(structured_features),
            key_extracted_signals={k: v for k, v in structured_features.items() if v > 0},
        )

        # Limitations declaration
        limitations = [
            "URL and domain analysis is static; deep sandboxing and dynamic payload execution are disabled for safety.",
            "ML model trained on standardized multi-class baseline features; continuous domain reputation feed integration planned for subsequent phase.",
            "SHAP explanations approximate local linear feature impact around prediction vector.",
            "Origin assessment and geolocation reflect technical infrastructure observables, not physical human identity.",
            "Attribution support provides technical correlation hypotheses and does not constitute definitive legal attribution."
        ]

        # 8. Update Legacy & Modern Response Fields
        legacy_indicators = [
            LegacyThreatIndicator(
                category=ind.category,
                feature=ind.indicator,
                description=ind.evidence,
                severity=ind.severity,
                observed_value=ind.weight,
            )
            for ind in risk_result.indicators
        ]

        legacy_class = risk_result.classification
        if legacy_class == ThreatClass.LEGITIMATE.value:
            legacy_class = "BENIGN"

        base_analysis.threat_assessment = InitialThreatAssessment(
            risk_score=risk_result.risk_score,
            classification=legacy_class,
            confidence=prediction_result.confidence,
            indicators=legacy_indicators,
            explanation=shap_result.explanation_summary,
        )

        # 8. Alert Evaluation & Real-Time Alert Object Generation
        from backend.app.services.alert_service import AlertService
        alert_eval = AlertService.evaluate_analysis(base_analysis)
        base_analysis.security_alert = alert_eval.alert

        # Attach Phase 2 AI, Explainability & Content outputs
        base_analysis.ai_inference = prediction_result
        base_analysis.risk_assessment = risk_result
        base_analysis.shap_explanation = shap_result
        base_analysis.content_intelligence = content_intelligence
        base_analysis.feature_summary = feature_summary
        base_analysis.observed_evidence = risk_result.indicators
        base_analysis.limitations = limitations


        # 9. Phase 3: Infrastructure Intelligence & Origin Assessment
        try:
            intel = await self.infra_service.gather_intelligence(base_analysis)
            base_analysis.infrastructure_intelligence = intel
            base_analysis.geolocation = intel.ip_intelligence
            base_analysis.origin_assessment = intel.origin_assessment
        except Exception as e:
            logger.warning(f"Infrastructure intelligence gathering error: {e}")
            intel = None

        # 9. Phase 3: Real NetworkX Threat Graph Construction
        try:
            G = ThreatGraphBuilder.build_case_graph(base_analysis, intel)
            graph_data = ThreatGraphBuilder.serialize_graph(G)
            base_analysis.threat_graph = graph_data
        except Exception as e:
            logger.warning(f"Threat graph generation error: {e}")

        # 10. Phase 3: Cross-Case Campaign Correlation & Persistence
        try:
            matches, campaign, attribution = await CorrelationPersistenceService.correlate_and_persist(
                analysis=base_analysis,
                intel=intel,
                session=db_session,
            )
            base_analysis.campaign_correlations = matches
            base_analysis.active_campaign = campaign
            base_analysis.attribution_support = attribution
        except Exception as e:
            logger.warning(f"Campaign correlation error: {e}")

        return base_analysis

    def analyze_bytes(self, raw_bytes: bytes, filename: Optional[str] = "uploaded.eml") -> EmailAnalysisResponse:
        """Synchronous wrapper for test execution and CLI tasks."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # In an active event loop, run directly in new loop via nest_asyncio or runner
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, self.analyze_bytes_async(raw_bytes, filename)).result()
            else:
                return loop.run_until_complete(self.analyze_bytes_async(raw_bytes, filename))
        except Exception:
            return asyncio.run(self.analyze_bytes_async(raw_bytes, filename))


# Global pipeline instance
pipeline = ThreatAnalysisPipeline()
