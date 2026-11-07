<!-- coderabbit-ai-generated:v1 -->

# ML model card

The deployed artifact remains the inherited Logistic Regression + TF-IDF/structured-feature baseline. It was trained with scikit-learn 1.7.2, now pinned to avoid untested artifact incompatibility. The demonstration corpus has 21 messages, three per class. `data/training/manifest.json` records its checksum, labels, source and unresolved authorship/license provenance. Repository MIT attribution is preserved; no external corpus has been imported.

Training now fits TF-IDF and scaling inside each fold, groups identical normalized text, and reserves a frozen seven-message holdout. Sender/campaign/thread group labels are absent. In the latest run, CV accuracy on the 14 training messages was 0.1429; holdout accuracy was 0.7143. Per-class metrics, confusion matrices, Brier score, errors and split indices are in `backend/app/ml/models/candidate_evaluation.json`. These results are not statistically meaningful or evidence of production accuracy. No additional model is justified with this sample size. Candidate artifacts remain outside Git, and the deployed artifact was not replaced.

Reproduce: `python -m backend.app.ml.train_model --output /tmp/mailspectra-candidate-model`. Windows: use an operator-chosen temporary directory instead. The saved candidate excludes held-out records from fitting. Metadata includes feature/library versions, dataset checksum and evaluation. Prediction probabilities remain uncalibrated. The rule fallback reports no probabilities and explicitly marks the model unavailable. SHAP and heuristic explanations retain distinct method names.

Required before operational use: verify dataset provenance/redistribution rights; obtain representative labelled groups; establish false-positive/negative costs and calibration; evaluate on a sufficiently large independent holdout. A passing software test does not satisfy these data requirements.
