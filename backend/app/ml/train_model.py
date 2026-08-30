import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.preprocessing import StandardScaler

# Ensure workspace root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from backend.app.core.logging import logger
from backend.app.ml.feature_extractor import FeatureExtractor, STRUCTURED_FEATURE_NAMES
from backend.app.ml.model_loader import ModelBundle, ModelLoader
from backend.app.ml.schemas import ThreatClass
from backend.app.services.email_parser import EmailForensicParser


DEFAULT_DATASET_PATH = Path(__file__).parent.parent.parent.parent / "data" / "training" / "dataset.json"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "models"


def load_dataset(dataset_path: Path) -> Tuple[List[str], List[Dict[str, float]], List[str], Dict[str, Any]]:
    """Parse raw .eml emails in dataset and extract text representations, structured features, and labels."""
    logger.info(f"Loading dataset from '{dataset_path}'...")
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    meta = data.get("_metadata", {})
    samples = data.get("samples", [])

    texts: List[str] = []
    structured_list: List[Dict[str, float]] = []
    labels: List[str] = []

    for item in samples:
        raw_eml_str = item["raw_eml"]
        label = item["label"]
        raw_bytes = raw_eml_str.encode("utf-8", errors="replace")

        parser = EmailForensicParser(raw_bytes=raw_bytes, filename=f"{item['id']}.eml")
        analysis = parser.parse()

        text = FeatureExtractor.extract_text(analysis)
        struct_feats = FeatureExtractor.extract_structured_features(analysis)

        texts.append(text)
        structured_list.append(struct_feats)
        labels.append(label)

    logger.info(f"Loaded {len(texts)} samples across {len(set(labels))} classes from dataset.")
    return texts, structured_list, labels, meta


def train_and_evaluate(
    dataset_path: Path = DEFAULT_DATASET_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Dict[str, Any]:
    """Train baseline multi-class threat classifier, evaluate metrics, and save model artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    texts, structured_list, labels, dataset_meta = load_dataset(dataset_path)

    unique_classes = sorted(list(set(labels)))
    n_samples = len(labels)

    # 1. Fit TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=500,
        sublinear_tf=True,
        stop_words="english",
    )
    X_text = vectorizer.fit_transform(texts)

    # 2. Fit Structured Features Scaler
    X_struct_raw = np.array(
        [[d.get(name, 0.0) for name in STRUCTURED_FEATURE_NAMES] for d in structured_list],
        dtype=np.float64,
    )
    scaler = StandardScaler()
    X_struct_scaled = scaler.fit_transform(X_struct_raw)

    # 3. Concatenate Sparse Feature Matrix
    X_combined = sparse.hstack([X_text, sparse.csr_matrix(X_struct_scaled)]).tocsr()

    # 4. Initialize Multi-Class Classifier
    classifier = LogisticRegression(
        C=1.0,
        max_iter=1000,
        class_weight="balanced",
        solver="lbfgs",
        random_state=42,
    )

    # 5. Model Evaluation (Stratified K-Fold / Leave-One-Out if small dataset)
    n_splits = min(3, min([labels.count(c) for c in unique_classes]))
    metrics_report: Dict[str, Any] = {
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_name": dataset_meta.get("dataset_name", "Demonstration Corpus"),
        "dataset_type": dataset_meta.get("dataset_type", "DEMONSTRATION"),
        "total_samples": n_samples,
        "classes": unique_classes,
        "n_splits": n_splits,
        "is_statistically_significant": n_samples >= 200,
        "limitations": [
            "Trained on demonstration dataset intended for pipeline verification and baseline scoring.",
            "Metrics reflect demonstration corpus distribution and should be benchmarked on enterprise datasets (e.g. Enron, Nazario) prior to mission-critical deployment."
        ],
    }

    if n_splits >= 2:
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
        try:
            y_pred_cv = cross_val_predict(classifier, X_combined, labels, cv=cv)
            accuracy = float(np.mean(y_pred_cv == np.array(labels)))
            f1_macro = float(f1_score(labels, y_pred_cv, average="macro", zero_division=0))
            f1_weighted = float(f1_score(labels, y_pred_cv, average="weighted", zero_division=0))
            prec_macro = float(precision_score(labels, y_pred_cv, average="macro", zero_division=0))
            rec_macro = float(recall_score(labels, y_pred_cv, average="macro", zero_division=0))
            cm = confusion_matrix(labels, y_pred_cv, labels=unique_classes).tolist()
            cls_report = classification_report(labels, y_pred_cv, zero_division=0, output_dict=True)

            metrics_report["cv_evaluation"] = {
                "accuracy": round(accuracy, 4),
                "f1_macro": round(f1_macro, 4),
                "f1_weighted": round(f1_weighted, 4),
                "precision_macro": round(prec_macro, 4),
                "recall_macro": round(rec_macro, 4),
                "confusion_matrix": cm,
                "classification_report": cls_report,
            }
        except Exception as e:
            logger.warning(f"Cross-validation note: {e}")
            metrics_report["cv_evaluation_error"] = str(e)

    # 6. Fit final model on all data
    classifier.fit(X_combined, labels)

    train_acc = float(classifier.score(X_combined, labels))
    metrics_report["training_accuracy"] = round(train_acc, 4)

    # 7. Create ModelBundle & Save
    bundle = ModelBundle(
        classifier=classifier,
        vectorizer=vectorizer,
        scaler=scaler,
        structured_feature_names=STRUCTURED_FEATURE_NAMES,
        classes=unique_classes,
        metadata={
            "version": "2.0.0",
            "model_type": "LogisticRegression (L2, Balanced) + TF-IDF (1-2 ngrams)",
            "n_samples": n_samples,
            "n_features_total": X_combined.shape[1],
            "n_text_features": X_text.shape[1],
            "n_structured_features": len(STRUCTURED_FEATURE_NAMES),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "training_accuracy": round(train_acc, 4),
        },
    )

    model_path = output_dir / "threat_classifier.joblib"
    ModelLoader.save_model(bundle, model_path=model_path)

    metrics_path = output_dir / "evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_report, f, indent=2)

    logger.info(f"Model saved to '{model_path}' and metrics to '{metrics_path}'")
    return metrics_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and evaluate DeepTrace AI Threat Detection Model")
    parser.add_argument("--data", type=str, default=str(DEFAULT_DATASET_PATH), help="Path to training dataset JSON")
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT_DIR), help="Output directory for model artifacts")
    args = parser.parse_args()

    metrics = train_and_evaluate(dataset_path=Path(args.data), output_dir=Path(args.output))
    print("\n================ DEEPTRACE MODEL TRAINING & EVALUATION REPORT ================")
    print(json.dumps(metrics, indent=2))
    print("==============================================================================\n")
