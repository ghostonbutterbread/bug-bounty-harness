# Analyze Endpoint Scripts

## `analyze_endpoint.py`

- **Purpose:** Parse a raw HTTP request into a sanitized, provenance-preserving
  endpoint-analysis artifact directory.
- **Inputs:** Program slug, raw request file, and optional source-lane metadata.
- **Outputs:** Sanitized endpoint records, request-shape evidence, and review
  artifacts under the selected output root.
- **Mutates:** Files only in the declared artifact location; it sends no target
  traffic.
- **Example:** `bbh skills/analyze-endpoint/scripts/analyze_endpoint.py <program> request.raw`
- **Verification:** `bbh skills/analyze-endpoint/scripts/analyze_endpoint.py --help`
- **Coverage:** Request parsing is deterministic; inferred route shapes are
  non-exhaustive seeds for agent review.
