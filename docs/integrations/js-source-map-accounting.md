# JS source-map accounting repair

- Objective: do not store, cache, or count HTTP error bodies or malformed source maps as downloaded maps; keep usable map extraction intact.
- Owner: Hermes; branch `fix/js-source-map-accounting`, worktree `/home/ryushe/projects/bbh-js-source-map-accounting`.
- Fetched base: `60a27386f531d32460e2175b017176e22de04597` (`origin/beta`); intended integration target: `beta`.
- Scope: `agents/js_analyzer.py`, `agents/test_js_analyzer.py`; no live target traffic or runtime activation.
- Evidence: four regression tests each failed on the intended missing behavior before implementation, then passed. First independent review of checkpoint `3d1c708` found empty-map status inconsistency; corrected with a two-run RED→GREEN test. `agents/test_js_analyzer.py`: 189 passed. `git diff --check` clean; final re-review and beta integration pending.
- Contract: only 2xx responses with version-3 JSON and a `sources` list enter the map cache/count. Failed or malformed fetches retain status but do not enter the cache. Existing invalid cached entries are ignored and refetched without deleting historical files.
- Historical policy: prior run manifests and `js_artifacts` rows remain immutable evidence; this change corrects future per-run metrics and refetches invalid cache entries without deleting or rewriting historical records. No current runtime reader derives an all-time download counter from `js_artifacts`; a historical backfill is a separate task if needed.
- Activation boundary: beta publication does not by itself switch a stable lane or refresh already-loaded agent code. The selected Hoster beta checkout is the runtime source.
- Next: commit review correction, obtain independent re-review, reconcile current `origin/beta`, run integrated tests, publish beta. Do not delete unrelated dirty checkout until the opt-in Chromium edit has an owner decision.
