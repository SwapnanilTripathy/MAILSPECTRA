import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple
import joblib
import hashlib
import sklearn
from sklearn.base import clone
from sklearn.model_selection import StratifiedGroupKFold
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
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[3] / "model-candidates"


def load_dataset(dataset_path: Path) -> Tuple[List[str], List[Dict[str, float]], List[str], Dict[str, Any]]:
    """Parse raw .eml emails in dataset and extract text representations, structured features, and labels."""
    logger.info(f"Loading dataset from '{dataset_path}'...")
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    manifest_path = dataset_path.with_name("manifest.json")
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("sha256") != hashlib.sha256(dataset_path.read_bytes()).hexdigest():
            raise ValueError("Dataset manifest checksum mismatch")
    meta = dict(data.get("_metadata", {}))
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

    meta["group_labels"] = [{k: item[k] for k in ("group_id", "campaign_id", "thread_id", "sender_id") if item.get(k)} for item in samples]
    logger.info(f"Loaded {len(texts)} samples across {len(set(labels))} classes from dataset.")
    return texts, structured_list, labels, meta


def train_and_evaluate(
    dataset_path: Path = DEFAULT_DATASET_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Dict[str, Any]:
    """Train baseline multi-class threat classifier, evaluate metrics, and save model artifacts."""
    output_dir = Path(output_dir)
    candidate_path = output_dir / "threat_classifier.joblib"
    if candidate_path.resolve() == ModelLoader.get_model_path().resolve():
        raise ValueError("Training cannot overwrite the deployed model; choose a candidate output directory")
    output_dir.mkdir(parents=True, exist_ok=True)
    texts, structured_list, labels, dataset_meta = load_dataset(dataset_path)

    unique_classes = sorted(list(set(labels)))
    n_samples = len(labels)

    vectorizer = TfidfVectorizer(ngram_range=(1,2), max_features=500, sublinear_tf=True, stop_words="english")
    X_struct_raw = np.array([[d.get(name,0) for name in STRUCTURED_FEATURE_NAMES] for d in structured_list], dtype=np.float64)
    scaler = StandardScaler()
    # Exact duplicate normalized text remains in the same fold. Sender/thread grouping
    # requires independently curated group metadata, unavailable in the inherited corpus.
    groups = np.array([hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest() for text in texts])
    # Union duplicate text and any supplied campaign/thread/sender group labels.
    parents = list(range(len(groups)))
    def root(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]; i = parents[i]
        return i
    seen = {}
    for i, digest in enumerate(groups):
        keys = [("text", str(digest))] + [(k, str(v)) for k,v in dataset_meta["group_labels"][i].items()]
        for key in keys:
            if key in seen: parents[root(i)] = root(seen[key])
            else: seen[key] = i
    groups = np.array([str(root(i)) for i in range(len(groups))])
    def matrices(train, test):
        vec, scale = clone(vectorizer), clone(scaler)
        train_text = vec.fit_transform([texts[i] for i in train])
        test_text = vec.transform([texts[i] for i in test])
        train_struct = scale.fit_transform(X_struct_raw[train])
        test_struct = scale.transform(X_struct_raw[test])
        return sparse.hstack([train_text, train_struct]).tocsr(), sparse.hstack([test_text,test_struct]).tocsr(), vec, scale

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
        "is_statistically_significant": False,
        "deployment_status": "DEMONSTRATION_ONLY",
        "production_ready": False,
        "per_class_support": {c:labels.count(c) for c in unique_classes},
        "limitations": [
            "Trained on demonstration dataset intended for pipeline verification and baseline scoring.",
            "Metrics reflect demonstration corpus distribution and should be benchmarked on enterprise datasets (e.g. Enron, Nazario) prior to mission-critical deployment."
        ],
    }

    if n_splits < 3:
        raise ValueError("At least three examples per class are needed for independent holdout and cross-validation")
    y = np.array(labels)
    holdout_split = (StratifiedKFold if len(set(groups)) == n_samples else StratifiedGroupKFold)(n_splits=3, shuffle=True, random_state=42)
    train_idx, holdout_idx = next(holdout_split.split(np.zeros(n_samples), y, groups))
    if set(y[train_idx]) != set(y):
        raise ValueError("Insufficient grouped data: training split omits a class")
    cv = (StratifiedKFold if len(set(groups[train_idx])) == len(train_idx) else StratifiedGroupKFold)(n_splits=2, shuffle=True, random_state=43)
    y_pred_cv = np.empty(len(train_idx), dtype=object)
    for tr, va in cv.split(np.zeros(len(train_idx)), y[train_idx], groups[train_idx]):
        xtr, xva, _, _ = matrices(train_idx[tr],train_idx[va])
        model = clone(classifier).fit(xtr,y[train_idx[tr]])
        y_pred_cv[va] = model.predict(xva)
    def evaluate(expected,predicted):
        return {"accuracy":float(np.mean(expected==predicted)), "f1_macro":float(f1_score(expected,predicted,average="macro",zero_division=0)), "f1_weighted":float(f1_score(expected,predicted,average="weighted",zero_division=0)), "confusion_matrix":confusion_matrix(expected,predicted,labels=unique_classes).tolist(), "classification_report":classification_report(expected,predicted,zero_division=0,output_dict=True)}
    metrics_report["cv_evaluation"] = evaluate(y[train_idx], y_pred_cv.tolist())
    X_combined, X_holdout, vectorizer, scaler = matrices(train_idx,holdout_idx)
    classifier.fit(X_combined,y[train_idx])
    holdout_predictions = classifier.predict(X_holdout)
    metrics_report["holdout_evaluation"] = evaluate(y[holdout_idx], holdout_predictions)
    probabilities = classifier.predict_proba(X_holdout)
    metrics_report["holdout_evaluation"]["multiclass_brier_score"] = float(np.mean(np.sum((probabilities - (y[holdout_idx,None] == classifier.classes_).astype(float))**2,axis=1)))
    metrics_report["holdout_evaluation"]["errors"] = [{"sample_index":int(i),"actual":str(actual),"predicted":str(pred)} for i,actual,pred in zip(holdout_idx,y[holdout_idx],holdout_predictions) if actual != pred]
    metrics_report["split"] = {"training_indices":train_idx.tolist(), "holdout_indices":holdout_idx.tolist(), "grouping":"Union of normalized-text duplicates and supplied group/campaign/thread/sender IDs", "group_ids":groups.tolist(), "training_size":len(train_idx), "holdout_size":len(holdout_idx), "preprocessing":"Fit on each training fold only", "random_seeds":[42,43]}
    metrics_report["is_statistically_significant"] = False
    metrics_report["dataset_sha256"] = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    metrics_report["calibration_status"] = f"Uncalibrated; reliability has not been established on the {len(holdout_idx)}-sample holdout"
    # Preserve the holdout exclusion when producing this candidate model.
    X_text = vectorizer.transform([texts[i] for i in train_idx])
    train_acc = float(classifier.score(X_combined, y[train_idx]))
    metrics_report["training_accuracy"] = round(train_acc, 4)

    # 7. Create ModelBundle & Save
    bundle = ModelBundle(
        classifier=classifier,
        vectorizer=vectorizer,
        scaler=scaler,
        structured_feature_names=STRUCTURED_FEATURE_NAMES,
        classes=unique_classes,
        metadata={
            "version": "3.0.0-candidate",
            "dataset_sha256": metrics_report["dataset_sha256"],
            "library_versions": {"scikit-learn":sklearn.__version__, "numpy":np.__version__},
            "feature_version":"structured-v1",
            "evaluation":metrics_report,
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
