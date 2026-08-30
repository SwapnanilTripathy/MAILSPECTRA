from typing import Any, Dict, List, Optional
import numpy as np
from scipy import sparse
import shap

from backend.app.core.logging import logger
from backend.app.ml.feature_extractor import FeatureExtractor
from backend.app.ml.model_loader import ModelBundle, ModelLoader
from backend.app.ml.schemas import SHAPExplanation, SHAPFeatureContribution, ThreatClass



FEATURE_HUMAN_DESCRIPTIONS: Dict[str, str] = {
    "auth_spf_pass": "Sender Policy Framework (SPF) validation passed",
    "auth_dkim_pass": "Cryptographic DKIM signature passed verification",
    "auth_dmarc_pass": "DMARC domain alignment policy passed",
    "auth_all_pass": "All email authentication protocols (SPF, DKIM, DMARC) verified",
    "auth_spf_fail": "Sender Policy Framework (SPF) validation failed",
    "auth_dkim_fail": "Cryptographic DKIM signature failed verification",
    "auth_dmarc_fail": "DMARC domain alignment policy failed",
    "auth_results_missing": "Email lacks standard authentication headers",
    "identity_reply_to_mismatch": "Reply-To header domain conflicts with sender domain",
    "identity_return_path_mismatch": "Return-Path domain does not match From sender domain",
    "identity_display_name_email_embed": "Display name embeds a deceptive email address",
    "identity_display_name_sender_mismatch": "Display name email conflicts with actual envelope sender",
    "identity_is_freemail_sender": "Sent from consumer freemail provider for corporate context",
    "identity_suspicious_tld": "Sender domain uses a high-risk or commonly abused TLD",
    "url_total_count": "Total number of hyperlinks detected in email",
    "url_unique_domains_count": "Number of distinct external domains linked",
    "url_ip_host_count": "Hyperlink points directly to raw IP address instead of domain",
    "url_shortener_count": "URL shortener detected hiding target destination",
    "url_suspicious_tld_count": "Hyperlinks pointing to suspicious top-level domains",
    "url_sender_domain_mismatch": "Hyperlinks point to domains unrelated to sender domain",
    "attachment_total_count": "Total email attachments",
    "attachment_suspicious_ext_count": "Attachment has high-risk executable or script extension",
    "attachment_macro_count": "Macro-enabled Microsoft Office document attached",
    "attachment_executable_count": "Direct binary executable payload attached",
    "relay_total_hops": "Number of mail transfer agent hops in relay path",
    "relay_origin_is_private": "Origin hop server resolved to an internal private RFC1918 IP",
    "content_urgency_keyword_count": "High-urgency / artificial pressure vocabulary detected",
    "content_credential_harvest_keyword_count": "Credential solicitation / login credential harvesting terms",
    "content_payment_wire_keyword_count": "Wire transfer, payment diversion, or invoice payment instructions",
    "content_account_suspension_keyword_count": "Account suspension, restricted access, or security warning terms",
    "content_impersonation_keyword_count": "Executive / VIP authority impersonation indicators",
    "content_suspicious_cta_keyword_count": "Aggressive call-to-action click triggers",
    "content_text_length": "Normalized message length factor",
    "content_html_to_text_ratio": "Disproportionate HTML layout structure relative to plain text",
}


class ThreatExplainer:
    """Computes SHAP feature importance values and transparent explanations for threat predictions."""

    def __init__(self, model_bundle: Optional[ModelBundle] = None, auto_load: bool = True):
        if model_bundle is not None:
            self.bundle = model_bundle
        elif auto_load:
            self.bundle = ModelLoader.load_model()
        else:
            self.bundle = None


    def explain(
        self,
        predicted_class: str,
        X: Optional[sparse.csr_matrix],
        structured_features: Dict[str, float],
    ) -> SHAPExplanation:
        """Generate SHAP explanation for the given prediction and feature matrix."""
        if not self.bundle or X is None:
            return self._fallback_explanation(predicted_class, structured_features)

        try:
            return self._compute_shap_explanation(predicted_class, X, structured_features)
        except Exception as e:
            logger.warning(f"SHAP explanation computation failed ({e}). Using feature contribution fallback.")
            return self._fallback_explanation(predicted_class, structured_features)

    def _compute_shap_explanation(
        self,
        predicted_class: str,
        X: sparse.csr_matrix,
        structured_features: Dict[str, float],
    ) -> SHAPExplanation:
        clf = self.bundle.classifier
        vec = self.bundle.vectorizer
        classes = list(self.bundle.classes)

        if predicted_class not in classes:
            return self._fallback_explanation(predicted_class, structured_features)

        class_idx = classes.index(predicted_class)

        # Assemble unified feature names (text TF-IDF vocabulary + structured feature names)
        tfidf_names = [f"word:'{w}'" for w in vec.get_feature_names_out()]
        struct_names = [f"signal:{name}" for name in self.bundle.structured_feature_names]
        all_feature_names = tfidf_names + struct_names

        # Convert sparse row to dense for SHAP calculation
        X_dense = X.toarray()
        background_baseline = np.zeros((1, X_dense.shape[1]), dtype=np.float64)

        # Compute SHAP values using LinearExplainer against reference zero baseline
        explainer = shap.LinearExplainer(clf, masker=shap.maskers.Independent(data=background_baseline))
        shap_values = explainer(X_dense)

        # SHAP values shape: (1, n_features, n_classes) or (1, n_features)
        if len(shap_values.values.shape) == 3:
            class_shap_vals = shap_values.values[0, :, class_idx]
            base_val = float(shap_values.base_values[0, class_idx])
        else:
            class_shap_vals = shap_values.values[0, :]
            base_val = float(shap_values.base_values[0]) if hasattr(shap_values, "base_values") else 0.0

        # Collect non-zero and top contributing features
        feature_tuples: List[SHAPFeatureContribution] = []
        for i, (name, val, shap_val) in enumerate(zip(all_feature_names, X_dense[0], class_shap_vals)):
            if abs(val) < 1e-6 and abs(shap_val) < 1e-4:
                continue

            # Format name and description
            if name.startswith("word:"):
                clean_name = name.replace("word:", "Keyword ")
                desc = f"Vocabulary term '{clean_name.replace('Keyword ', '')}' in email body/subject"
            elif name.startswith("signal:"):
                raw_sig = name.replace("signal:", "")
                clean_name = raw_sig.replace("_", " ").title()
                desc = FEATURE_HUMAN_DESCRIPTIONS.get(raw_sig, f"Forensic observable: {clean_name}")
            else:
                clean_name = name
                desc = f"Observed feature: {name}"

            # Direction relative to threat
            if predicted_class == ThreatClass.LEGITIMATE.value:
                direction = "decreases_risk" if shap_val > 0 else "increases_risk"
            else:
                direction = "increases_risk" if shap_val > 0 else "decreases_risk"

            feature_tuples.append(
                SHAPFeatureContribution(
                    feature=name,
                    feature_name=clean_name,
                    value=round(float(val), 3),
                    contribution=round(float(shap_val), 4),
                    direction=direction,
                    description=desc,
                )
            )

        # Sort by absolute contribution descending
        feature_tuples.sort(key=lambda x: abs(x.contribution), reverse=True)
        top_features = feature_tuples[:8]


        # Generate summary
        top_risk_drivers = [f.feature_name for f in top_features if f.direction == "increases_risk"]
        summary = (
            f"The model predicted '{predicted_class}' driven primarily by: "
            f"{', '.join(top_risk_drivers[:3]) if top_risk_drivers else 'standard baseline profile'}."
        )

        return SHAPExplanation(
            predicted_class=predicted_class,
            base_value=round(base_val, 4),
            top_features=top_features,
            explanation_summary=summary,
            method="SHAP LinearExplainer",
        )

    def _fallback_explanation(
        self, predicted_class: str, structured_features: Dict[str, float]
    ) -> SHAPExplanation:
        """Heuristic explanation when SHAP or ML model is unavailable."""
        top_features: List[SHAPFeatureContribution] = []

        for name, val in structured_features.items():
            if val <= 0:
                continue

            desc = FEATURE_HUMAN_DESCRIPTIONS.get(name, name.replace("_", " ").title())
            clean_name = name.replace("_", " ").title()
            
            # Simple heuristic weight
            weight = min(0.35, val * 0.15) if "fail" in name or "mismatch" in name or "ip_host" in name else 0.10

            top_features.append(
                SHAPFeatureContribution(
                    feature=f"signal:{name}",
                    feature_name=clean_name,
                    value=round(float(val), 2),
                    contribution=round(float(weight), 3),
                    direction="increases_risk" if predicted_class != ThreatClass.LEGITIMATE.value else "decreases_risk",
                    description=desc,
                )
            )

        top_features.sort(key=lambda x: abs(x.contribution), reverse=True)
        top_features = top_features[:6]

        summary = (
            f"Heuristic feature analysis for '{predicted_class}'. "
            f"Key contributing factors: {', '.join([f.feature_name for f in top_features[:3]]) if top_features else 'Clean email profile'}."
        )

        return SHAPExplanation(
            predicted_class=predicted_class,
            base_value=0.0,
            top_features=top_features,
            explanation_summary=summary,
            method="Heuristic Feature Attribution (Fallback)",
        )
