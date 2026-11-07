<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:ab11f8069966d5870b49b13da7ec2ed26723233fc5b49158f131441d251c5770 -->

# ML model card

The deployed artifact remains the inherited Logistic Regression + TF-IDF/structured-feature baseline. It was trained with scikit-learn 1.7.2, now pinned to avoid untested artifact incompatibility. The demonstration corpus has 21 messages, three per class. `data/training/manifest.json` records its checksum, labels, source and unresolved authorship/license provenance. Repository MIT attribution is preserved; no external corpus has been imported.

Training now fits TF-IDF and scaling inside each fold, groups identical normalized text, and reserves a frozen seven-message holdout. Sender/campaign/thread group labels are absent. In the latest run, CV accuracy on the 14 training messages was 0.1429; holdout accuracy was 0.7143. Per-class metrics, confusion matrices, Brier score, errors and split indices are in `backend/app/ml/models/candidate_evaluation.json`. These results are not statistically meaningful or evidence of production accuracy. No additional model is justified with this sample size. Candidate artifacts remain outside Git, and the deployed artifact was not replaced.

Training defaults to the ignored repository `model-candidates/` directory. It refuses an output file resolving to the deployed artifact (including symlink aliases); saving a candidate also preserves the active model cache. This changes the previous default that wrote directly into the bundled model directory. Deployment is a separate reviewed action after data rights and evaluation requirements are satisfied. Calibration status reports the actual holdout size.

Reproduce: `python -m backend.app.ml.train_model --output /tmp/mailspectra-candidate-model`. Windows: use an operator-chosen temporary directory instead. The saved candidate excludes held-out records from fitting. Metadata includes feature/library versions, dataset checksum and evaluation. Prediction probabilities remain uncalibrated. The rule fallback reports no probabilities and explicitly marks the model unavailable. SHAP and heuristic explanations retain distinct method names.

Required before operational use: verify dataset provenance/redistribution rights; obtain representative labelled groups; establish false-positive/negative costs and calibration; evaluate on a sufficiently large independent holdout. A passing software test does not satisfy these data requirements.


<!-- /coderabbit-ai-generated:v1 -->