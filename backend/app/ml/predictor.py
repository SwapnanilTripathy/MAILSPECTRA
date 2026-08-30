from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Optional, Tuple
import numpy as np
from scipy import sparse

from backend.app.core.logging import logger
from backend.app.ml.feature_extractor import FeatureExtractor
from backend.app.ml.model_loader import ModelBundle, ModelLoader
from backend.app.ml.schemas import MLPredictionResult, ThreatClass

if TYPE_CHECKING:
    from backend.app.schemas.analysis import EmailAnalysisResponse



ALL_THREAT_CLASSES = [
    ThreatClass.LEGITIMATE.value,
    ThreatClass.PHISHING.value,
    ThreatClass.BUSINESS_EMAIL_COMPROMISE.value,
    ThreatClass.IMPERSONATION.value,
    ThreatClass.FRAUD.value,
    ThreatClass.CREDENTIAL_HARVESTING.value,
    ThreatClass.SUSPICIOUS.value,
]


class ThreatPredictor:
    """Performs inference using trained ML classifier or resilient heuristic fallback."""

    def __init__(self, model_bundle: Optional[ModelBundle] = None, auto_load: bool = True):
        if model_bundle is not None:
            self.bundle = model_bundle
        elif auto_load:
            self.bundle = ModelLoader.load_model()
        else:
            self.bundle = None

    def build_feature_matrix(
        self, text: str, structured_dict: Dict[str, float]
    ) -> Tuple[Optional[sparse.csr_matrix], Optional[np.ndarray]]:
        """Transform text and structured features into model input matrix."""
        if not self.bundle:
            return None, None

        # Text features
        text_features = self.bundle.vectorizer.transform([text])

        # Structured features
        struct_vec = np.array(
            [[structured_dict.get(name, 0.0) for name in self.bundle.structured_feature_names]],
            dtype=np.float64,
        )
        if self.bundle.scaler:
            struct_vec = self.bundle.scaler.transform(struct_vec)

        # Concatenate sparse text features with dense structured features
        combined_matrix = sparse.hstack([text_features, sparse.csr_matrix(struct_vec)]).tocsr()
        return combined_matrix, struct_vec

    def predict(self, analysis: EmailAnalysisResponse) -> Tuple[MLPredictionResult, Optional[sparse.csr_matrix]]:
        """Predict threat class and probabilities for a parsed email."""
        text = FeatureExtractor.extract_text(analysis)
        structured_dict = FeatureExtractor.extract_structured_features(analysis)

        if not self.bundle:
            fallback = self._heuristic_fallback(analysis, structured_dict)
            return fallback, None


        try:
            X, _ = self.build_feature_matrix(text, structured_dict)
            if X is None:
                fallback = self._heuristic_fallback(analysis, structured_dict)
                return fallback, None

            probs = self.bundle.classifier.predict_proba(X)[0]
            classes = list(self.bundle.classes)

            prob_dict: Dict[str, float] = {}
            for cls_name, p in zip(classes, probs):
                prob_dict[cls_name] = round(float(p), 4)

            # Ensure all threat classes exist in dictionary
            for tc in ALL_THREAT_CLASSES:
                if tc not in prob_dict:
                    prob_dict[tc] = 0.0

            # Find best class
            best_idx = int(np.argmax(probs))
            best_class = str(classes[best_idx])
            best_conf = round(float(probs[best_idx]), 4)

            return (
                MLPredictionResult(
                    predicted_class=best_class,
                    confidence=best_conf,
                    probabilities=prob_dict,
                    is_model_available=True,
                    model_version=self.bundle.metadata.get("version", "1.0.0"),
                    model_type=self.bundle.metadata.get("model_type", "LogisticRegression + TF-IDF"),
                ),
                X,
            )

        except Exception as e:
            logger.error(f"Prediction exception: {e}. Falling back to rule inference.", exc_info=True)
            fallback = self._heuristic_fallback(analysis, structured_dict)
            return fallback, None

    def _heuristic_fallback(
        self, analysis: EmailAnalysisResponse, structured_dict: Dict[str, float]
    ) -> MLPredictionResult:
        """Heuristic fallback prediction when ML model is unavailable."""
        prob_dict = {tc: 0.05 for tc in ALL_THREAT_CLASSES}

        # Check BEC signals
        if (
            structured_dict.get("content_payment_wire_keyword_count", 0) > 0
            and structured_dict.get("content_impersonation_keyword_count", 0) > 0
        ):
            pred_class = ThreatClass.BUSINESS_EMAIL_COMPROMISE.value
            confidence = 0.75
            prob_dict[pred_class] = 0.75
            prob_dict[ThreatClass.LEGITIMATE.value] = 0.05

        # Check Impersonation
        elif (
            structured_dict.get("identity_display_name_sender_mismatch", 0) > 0
            or structured_dict.get("identity_reply_to_mismatch", 0) > 0
        ):
            pred_class = ThreatClass.IMPERSONATION.value
            confidence = 0.70
            prob_dict[pred_class] = 0.70
            prob_dict[ThreatClass.LEGITIMATE.value] = 0.08

        # Check Credential Harvesting / Phishing
        elif (
            structured_dict.get("url_ip_host_count", 0) > 0
            or structured_dict.get("content_credential_harvest_keyword_count", 0) > 0
            or structured_dict.get("auth_spf_fail", 0) > 0
        ):
            if structured_dict.get("content_credential_harvest_keyword_count", 0) > 0:
                pred_class = ThreatClass.CREDENTIAL_HARVESTING.value
            else:
                pred_class = ThreatClass.PHISHING.value
            confidence = 0.72
            prob_dict[pred_class] = 0.72
            prob_dict[ThreatClass.LEGITIMATE.value] = 0.05

        # Check Suspicious Attachment
        elif structured_dict.get("attachment_suspicious_ext_count", 0) > 0:
            pred_class = ThreatClass.SUSPICIOUS.value
            confidence = 0.65
            prob_dict[pred_class] = 0.65
            prob_dict[ThreatClass.LEGITIMATE.value] = 0.10

        else:
            pred_class = ThreatClass.LEGITIMATE.value
            confidence = 0.85
            prob_dict[ThreatClass.LEGITIMATE.value] = 0.85

        # Normalize
        total_p = sum(prob_dict.values())
        prob_dict = {k: round(v / total_p, 4) for k, v in prob_dict.items()}

        return MLPredictionResult(
            predicted_class=pred_class,
            confidence=prob_dict[pred_class],
            probabilities=prob_dict,
            is_model_available=False,
            model_version="rule-fallback",
            model_type="Heuristic Rule-Engine",
        )
