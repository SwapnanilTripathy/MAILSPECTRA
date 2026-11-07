<!-- coderabbit-ai-generated:v1 -->

# Risk policy 3.0

The canonical assessment is `risk_assessment`; the legacy `threat_assessment` summary copies its score/classification. New cases, alerts and reports share it. Historical snapshots retain their original assessment version and are not silently rescored.

Caps sum to 100: model 40, authentication 15, identity 15, URL 15, attachment 10, content 5. Each inherited rule bucket is proportionally normalized from its original cap. The score is exactly the sum of those bounded components. An unavailable model contributes no probability points and is explicitly unavailable; this is not evidence of safety. Reported authentication failures are labelled unverified header claims. A reported pass no longer suppresses the score. These weights are a transparent engineering policy, not a calibrated probability of harm.

`core/assessment.py` defines severity: informational below 20, low at 20, medium at 40, high at configured `ALERT_THRESHOLD_SCORE` (60), critical at configured `CRITICAL_ALERT_SCORE` (80). Dashboard, alerts and PDFs use that function. UI verdict uses the returned severity. Low scores with an available model retain the inherited legitimate decision category; model-only prediction remains visible separately. Without a model and sufficient rules the final classification is UNKNOWN.

Repeated evidence within a category is capped, and attachment macro/executable branches are mutually exclusive. Model features and explicit rules overlap: they are not independent evidence, and this residual correlation must be evaluated before production. Indicator weights describe normalized contributions, not probabilities. The old clipped 170-point policy is deliberately replaced. A BEC fixture formerly above 60 scores 59.75 (medium) under the new allocation; tests verify the sum and classification instead of asserting the old score.
