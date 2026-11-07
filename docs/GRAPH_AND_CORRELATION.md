<!-- coderabbit-ai-generated:v1 -->

# Graph and campaign evidence

Graph nodes use `node_type`; edges include relationship, evidence text, artifact/schema references, provenance and source type. A Received header creates its asserted from-host → by-host relationship; the system does not invent links across gaps. Uploaded relay relationships are untrusted observations. Provider-derived edges are labelled separately, including offline fixtures.

Density uses a simple directed projection without self-loops, so duplicate edges cannot inflate density beyond one. Connected components use the undirected projection. The UI supports node and relationship filters, keyboard node selection, keyboard/pointer panning, zoom, evidence inspection and JSON export.

Correlation compares exact public IPs, domains, URLs and sender strings. It stores the actual shared values as well as the rule categories. Scores are bounded rule support, not a probability of a common actor. `CORRELATION_MATCH_THRESHOLD` defaults to 0.35 and cluster threshold to 0.60. Persistence considers the latest 500 ingested cases within `CORRELATION_WINDOW_DAYS` (90); this is an explicitly bounded search, not a complete historical search. Ingestion timestamps are used because supplied email dates can be forged.

Campaign IDs derive from shared evidence; existing membership is unioned on update. Shared infrastructure lists contain matched values, not every current indicator. Document/private IPs are not treated as public infrastructure for matching. A passing reported SPF/DKIM header no longer asserts an authenticated sender; unsupported identity/actor claims yield insufficient evidence or a possible identity inconsistency.
