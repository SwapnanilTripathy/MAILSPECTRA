<!-- coderabbit-ai-generated:v1 -->

# Analysis API contracts

The versioned analysis response remains backward compatible with the inherited field names and adds `schema_version: 1.1`. `backend/app/schemas/analysis.py` is the authority. Generate TypeScript declarations with `python -m scripts.generate_api_types`; `frontend/src/types/analysis.d.ts` includes all nested schema definitions and uses `unknown` for unconstrained extension payloads.

Frontend bindings use `node_type`, top-level graph metrics, relay `from_ip`/`hop_index`/`timestamp_iso`, domain `dns` and top-level lexical fields, `related_case_id`/`correlation_score`, attribution `assessment`, and attachment `size_bytes`. Missing metrics are unavailable; zero values remain zero. Indicator display defangs values while deliberate copy returns the original.

`frontend/tests/fixtures/analysis.json` is synthetic API-shaped data. `npm test` renders five forensic panels against it and checks the existing privacy utility. No provider findings in that fixture represent live observations.
