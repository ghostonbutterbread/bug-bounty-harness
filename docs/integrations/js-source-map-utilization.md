# JS source-map utilization integration dossier

- Status: implementation complete; awaiting independent review and beta integration.
- Owner: Hermes Agent.
- Feature branch: `feat/js-source-map-utilization`.
- Worktree: `/home/ryushe/worktrees/bbh-js-source-map-utilization`.
- Base: `beta` at `d4c8b29210eee1963450a3bf030c8da9d8a75429`.
- Intended integration target: `beta`; stable `master` promotion is requested after beta integration and verification.

## Contract

`agents/js_analyzer.py inventory` automatically follows an in-scope bundle's `sourceMappingURL`, uses a bounded fetch, retains valid maps content-addressed in `_library/sourcemaps/`, inventories all original module names in `source_map_modules.jsonl`, and creates bounded packets from embedded `sourcesContent`. The map URL and bundle/map SHA values remain attached to packet and metadata evidence. Maps outside the configured scope are not fetched. Oversized, unavailable, malformed, disabled, and cached maps are recorded explicitly rather than silently treated as coverage.

## Evidence and gates

- Focused test: `uv run --with pytest pytest agents/test_js_analyzer.py -q` — passed (18 tests) after review fixes.
- CLI syntax/help: `python3 -m py_compile agents/js_analyzer.py && python3 agents/js_analyzer.py inventory --help` — passed.
- Independent review: resolved the high-severity redirect finding by disabling automatic redirects for source-map fetches; a focused test verifies the no-redirect handler.
- Deferred: beta merge, post-merge focused tests, and explicit stable-branch promotion.

## Next action

Reconcile the reviewer result, inspect the staged diff, commit this coherent change, merge it into a clean current `beta`, rerun focused tests, then promote `beta` to `master` under the user's explicit request.
