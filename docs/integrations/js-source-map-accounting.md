# JS source-map accounting repair

- Objective: do not store, cache, or count HTTP error bodies or malformed source maps as downloaded maps; keep usable map extraction intact.
- Owner: Hermes; branch `fix/js-source-map-accounting`, worktree `/home/ryushe/projects/bbh-js-source-map-accounting`.
- Fetched base: `60a27386f531d32460e2175b017176e22de04597` (`origin/beta`); intended integration target: `beta`.
- Scope: `agents/js_analyzer.py`, `agents/test_js_analyzer.py`; no live target traffic or runtime activation.
- Evidence: three regression tests each failed on the intended missing behavior before implementation, then passed. `agents/test_js_analyzer.py`: 188 passed. Focused suite and `git diff --check` clean; independent review and beta integration pending.
- Contract: only 2xx responses with version-3 JSON and a `sources` list enter the map cache/count. Failed or malformed fetches retain status but do not enter the cache. Existing invalid cached entries are ignored and refetched without deleting historical files.
- Next: commit recoverable checkpoint, independent review, reconcile current `origin/beta`, run integrated tests, publish beta. Do not delete unrelated dirty checkout until the opt-in Chromium edit has an owner decision.
