# JavaScript cache freshness integration dossier

- **Status:** blocked pending independent review and activation gates
- **Owner:** Hermes delegated BBH cache task
- **Branch:** `fix/js-cache-freshness`
- **Worktree:** `/home/ryushe/worktrees/bbh-js-cache-freshness`
- **Base commit:** `ffbf641c3ae459aa030e494c9e5d3838c7f47699` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-06
- **Owning feature branch/ref:** `fix/js-cache-freshness`
- **Latest immutable recovery checkpoint:** base above; implementation checkpoint to be recorded in a later dossier-only commit
- **Feature implementation commit(s):** pending checkpoint
- **Inspiration / canonical references:** prior offline acquisition-cache review; `js-pull` freshness contract; existing `agents/js_analyzer.py`

## Intent

Prevent historical or stale URL mappings from suppressing acquisition, and prevent processing cached bytes from being reported as a new successful fetch. Extend the existing analyzer, not a new downloader. No data import, live collection, deployment, or publication is authorized in this task.

## Implemented contract

- URL reuse requires a 2xx status and a timezone-aware `last_fetched_at` within seven days, not in the future. Historical `last_seen` is not trustworthy: old versions updated it on cache reuse. Missing, invalid, future, or old fetch markers and unknown/failed status force a fetch; only a successful nonempty HTTP bundle response creates the marker. Unknown status remains unknown on failed refresh.
- Ordinary and `--skip-cached-processing` reuse apply the same freshness gate; `--refresh` overrides reuse. Existing skip behavior does not hash-check the cached body. Content-addressed file reuse following an actual fetch still advances the successful-fetch marker.
- Reprocessing carries the fetch marker through URL ledger, metadata and SQLite `last_seen`; it does not claim the current processing time as a fetch. Legacy metadata rows without this marker project NULL `last_seen` when replayed, not their `generated_at`. Inline scripts have no direct bundle-fetch marker. The index is still a rebuildable projection; untouched pre-existing imported/index rows can retain untrusted historical values. `js_files.last_seen` in a replay with several URLs for the same hash reflects the most recently replayed metadata row, not necessarily the latest fetch across all aliases. Do not use historical SQLite `last_seen` as proof of acquisition age.
- The current `js-pull` SQL example uses `last_seen < ...` and omits NULL rows; it is not a complete stale/unknown selection. Cache enforcement is on the analyzer URL ledger's `last_fetched_at`. Follow-up skill-owner review must correct that guidance without assuming old timestamps are trustworthy.
- A source-map cache has separate existing semantics; this change does not age it. The seven-day window is fixed, not a newly configurable program-specific option.

## Evidence and review

- Strict tracer RED: legacy URL with future `last_seen` and no fetch marker produced zero fetches in both ordinary and skip paths; both tests failed on call count. GREEN: both passed after freshness enforcement.
- Strict tracer RED: ordinary fresh cache replay made SQLite alias `last_seen` equal current processing time rather than the prior fetch; GREEN after propagating the marker into metadata and index.
- Offline synthetic suite: `python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py -q --tb=short`, with private HOME/XDG/artifact/tmp roots, socket-blocking `sitecustomize` inherited by subprocesses, pinned tree-sitter dependencies installed from local uv cache into scratch, and `PYTHONPATH` resolving this feature worktree: **634 passed**. This includes flags, successful re-fetch with identical bytes, status/timestamp unknowns, failed refresh, and timestamp preservation.
- First full-suite attempt: 274 failed, 358 passed because the borrowed interpreter lacked pinned parser dependencies. After scratch-only offline installation, 8 guard-induced failures showed the socket guard's `RuntimeError` bypassed normal transport error handling. Changing the guard to `OSError` still prohibits socket connections and yielded the passing suite above. No target network requests were sent.
- `git diff --check` passed. Added-line privacy scan for common private-key/token patterns and selected local paths reported zero matches; this is a bounded scan, not proof of absence of all secrets.
- Independent review: not yet performed. Integration, runtime activation, data import and branch propagation remain parent-owned.
- Fetched `origin/beta` contained both known earlier Hoster and storage-release commits; local `beta` checkout was divergent and was not changed. Repository-local instruction requires features to start at fetched beta; repair propagation to affected descendants/stable must be assessed by integrator rather than performed here.

## Blockers and deferred work

1. **Independent review:** rerun the offline synthetic suite and inspect the precise diff, especially SQLite legacy replay and shared-hash alias semantics; required before integration. Trigger: parent assigns independent reviewer.
2. **Existing writers are unsafe:** old active/release writer versions do not enforce this marker and can remove it or falsely advance `last_seen`. This branch alone does not protect data while they run. Integrator must release and verify the corrected code at every writer before reconciliation; test mixed-version replay, old writer rollback/compatibility and complete import fixtures in a coordinated pause.
3. **Historical evidence and migration:** no status or fetch time may be invented. In particular, historical Trello mappings with unknown status must stay unknown; Pinterest first-seen timestamps do not establish successful fetch time. A reviewed importer, complete real-store dry run, fresh verified backups, no-clobber publication/recovery and repeat readback remain necessary. Trigger: all writer versions corrected and owner-authorized coordinated pause. No prior staged migration was applied.
4. **Guidance/index semantics:** update `js-pull` stale/unknown SQL and explicitly assess existing untouched legacy SQLite values; tests need legacy rows, NULL, replay and same-hash multiple aliases. This blocks claiming that SQL or all old index rows now represent last successful fetch.
5. **Runtime and delivery:** feature branch only; no push, merge, Hoster activation, storage reconciliation, or stable propagation. Parent should fetch beta again before review/integration and reconcile if it moved.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/js-cache-freshness`
- **Latest immutable recovery checkpoint:** to be recorded after implementation commit.
- **Exact resume point:** independent review of implementation, then address or explicitly gate the blockers above; no production state touched.
- **Working-tree state at handoff:** expected clean after checkpoint.

## Decision gates

- **Integration:** independent review and focused suite pass; beta re-fetch and ancestry check.
- **Activation / cohort:** verify every writer's deployed revision and compatible behavior before any import; historical data requires separate safe publication procedure.
- **Promotion:** separate owner decision and stable/descendant propagation under lifecycle policy.

## Decision record

- 2026-11-06 — feature constructed on fetched beta; branch checkpoint only, no deployment or data modification.
