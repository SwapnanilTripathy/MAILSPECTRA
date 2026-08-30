import os
from pathlib import Path
from typing import Any, Dict, Optional
import joblib

from backend.app.core.logging import logger

DEFAULT_MODEL_DIR = Path(__file__).parent / "models"
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "threat_classifier.joblib"


class ModelBundle:
    """Container for the loaded machine learning pipeline artifacts."""

    def __init__(
        self,
        classifier: Any,
        vectorizer: Any,
        scaler: Any,
        structured_feature_names: list,
        classes: list,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.classifier = classifier
        self.vectorizer = vectorizer
        self.scaler = scaler
        self.structured_feature_names = structured_feature_names
        self.classes = classes
        self.metadata = metadata or {}


class ModelLoader:
    """Manages loading, saving, caching, and versioning of trained threat models."""

    _cached_bundle: Optional[ModelBundle] = None

    @classmethod
    def get_model_path(cls) -> Path:
        return DEFAULT_MODEL_PATH

    @classmethod
    def load_model(cls, model_path: Optional[Path] = None, force_reload: bool = False) -> Optional[ModelBundle]:
        """Load and cache the trained model bundle. Returns None if model is unavailable."""
        if cls._cached_bundle is not None and not force_reload:
            return cls._cached_bundle

        target_path = model_path or cls.get_model_path()
        if not target_path.exists():
            logger.warning(f"ML Model file not found at '{target_path}'. Operating in rule-fallback mode.")
            return None

        try:
            artifact = joblib.load(target_path)
            bundle = ModelBundle(
                classifier=artifact["classifier"],
                vectorizer=artifact["vectorizer"],
                scaler=artifact.get("scaler"),
                structured_feature_names=artifact["structured_feature_names"],
                classes=artifact["classes"],
                metadata=artifact.get("metadata", {}),
            )
            cls._cached_bundle = bundle
            logger.info(f"Loaded ML model successfully (Version: {bundle.metadata.get('version', '1.0.0')})")
            return bundle
        except Exception as e:
            logger.error(f"Failed to load ML model artifact from '{target_path}': {e}", exc_info=True)
            return None

    @classmethod
    def save_model(cls, bundle: ModelBundle, model_path: Optional[Path] = None) -> Path:
        """Persist model bundle to disk."""
        target_path = model_path or cls.get_model_path()
        target_path.parent.mkdir(parents=True, exist_ok=True)

        artifact = {
            "classifier": bundle.classifier,
            "vectorizer": bundle.vectorizer,
            "scaler": bundle.scaler,
            "structured_feature_names": bundle.structured_feature_names,
            "classes": bundle.classes,
            "metadata": bundle.metadata,
        }

        joblib.dump(artifact, target_path)
        cls._cached_bundle = bundle
        logger.info(f"ML Model successfully saved to '{target_path}'")
        return target_path

    @classmethod
    def clear_cache(cls) -> None:
        cls._cached_bundle = None
