# JavaScript cache freshness integration dossier

- **Status:** blocked pending independent review and activation gates
- **Owner:** Hermes delegated BBH cache task
- **Branch:** `fix/js-cache-freshness`
- **Worktree:** `/home/ryushe/worktrees/bbh-js-cache-freshness`
- **Base commit:** `ffbf641c3ae459aa030e494c9e5d3838c7f47699` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-06
- **Owning feature branch/ref:** `fix/js-cache-freshness`
- **Latest immutable recovery checkpoint before review repairs:** `859f95d2be9ef22a296af8a5d469573c6299d302`
- **Feature implementation commit(s):** `af701926318859e60fe02af60f57faa7da4ecd6c`
- **Inspiration / canonical references:** prior offline acquisition-cache review; `js-pull` freshness contract; existing `agents/js_analyzer.py`

## Intent

Prevent historical or stale URL mappings from suppressing acquisition, and prevent processing cached bytes from being reported as a new successful fetch. Extend the existing analyzer, not a new downloader. No data import, live collection, deployment, or publication is authorized in this task.

## Implemented contract

- URL reuse requires a 2xx status and a timezone-aware `last_fetched_at` within seven days, not in the future. Historical `last_seen` is not trustworthy: old versions updated it on cache reuse. Missing, invalid, future, or old fetch markers and unknown/failed status force a fetch; only a successful nonempty HTTP bundle response creates the marker. Unknown status remains unknown on failed refresh.
- Ordinary and `--skip-cached-processing` reuse apply the same freshness gate; `--refresh` overrides reuse. Existing skip behavior does not hash-check the cached body. Content-addressed file reuse following an actual fetch still advances the successful-fetch marker.
- SQLite replay aggregates first/last observation (`generated_at`) separately from maximum trusted `last_fetched_at`, per hash and per URL/hash. A later legacy row cannot erase a fetch marker; an older alias cannot regress the hash aggregate. Migration adds `last_fetched_at` and clears ambiguous old index seen times before rebuilding from metadata; untouched rows without replayed metadata have unknown times. Inline scripts have no direct bundle-fetch marker.
- The `js-pull` stale selector now uses the ledger's current URL mapping and includes unknown, invalid, future, non-2xx and stale fetches; historical aliases do not cause a fresh current URL to be selected.
- Inventory and observe serialize all library operations, including the entire ledger read–modify–write cycle, JSONL publication and index rebuild, using a persistent `.js-writer.lock` advisory `flock` per library. The lock is released on normal return, exceptions and cancellation; kernel close releases it on process death. Do not delete or replace the lock file while writers may exist. This requires a shared filesystem with working interprocess `flock`; old binaries and other writers do not participate and must be externally stopped/fenced before using the corrected writer. Runs sharing a library now wait for the whole preceding inventory, including network operations.
- A source-map cache has separate existing semantics; this change does not age it. The seven-day window is fixed, not a newly configurable program-specific option.

## Evidence and review

- Strict tracer RED: legacy URL with future `last_seen` and no fetch marker produced zero fetches in both ordinary and skip paths; both tests failed on call count. GREEN: both passed after freshness enforcement.
- Original tracer RED: ordinary fresh cache replay made the former SQLite fetch-time projection equal current processing time rather than the prior fetch. This review repair separates observation `last_seen` from the `last_fetched_at` projection.
- Review-repair RED: two inventory processes produced only `b.js` in the final ledger, and replay lacked an independently aggregated `last_fetched_at`; both reproduction regressions failed on `859f95d2`. The old documentation lacked a current-ledger selector. A second RED showed inventory and observe each resolved their library path twice, risking locking one library and writing another if config changed while waiting. The corrected commands resolve once and use that same result throughout.
- Review-repair focused GREEN: **15 passed** (`agents/test_js_cache_review.py`, `agents/test_js_analyzer.py::test_fresh_cache_reprocessing_preserves_fetch_time_in_ledger_and_index`, and `agents/test_js_analyzer_wayback.py::test_parser_budget_must_be_positive_before_any_paths_or_io`). Includes competing inventory processes, observe vs inventory, terminated writer, `RuntimeError`/`KeyboardInterrupt`/`SystemExit` release, migration, alias/hash replay, selector execution, resolve-once, and validation-before-I/O. A further RED showed lexicographic comparison accepted an invalid fetch marker and mishandled UTC offsets; replay now validates aware timestamps and compares instants. `strace -f --seccomp-bpf -e trace=connect` recorded zero connect syscalls. Private HOME/XDG/artifact/temp/config paths and an inherited Python socket guard were checked before imports; parser was enabled from the scratch dependencies.
- Initial review-repair full run: **661 passed, 2 failed** because the new wrapper resolved paths before validating parser byte limits. Moved all existing inventory argument validation before path resolution; the two previously failing cases pass in the focused run above.
- Final isolated full JS suite: **664 passed in 759.10s** across `agents/test_js_analyzer.py`, `agents/test_js_analyzer_wayback.py`, `agents/test_js_cache_review.py`, and `agents/test_js_artifact_review_regressions.py`. `strace -f --seccomp-bpf -e trace=connect` recorded **zero connect syscalls** across the suite and descendants. The test runner used private HOME/XDG/artifact/temp/config overrides and an inherited socket guard, with tree-sitter enabled.
- Intermediate isolated full JS suite: **663 passed in 383.17s** across `agents/test_js_analyzer.py`, `agents/test_js_analyzer_wayback.py`, `agents/test_js_cache_review.py`, and `agents/test_js_artifact_review_regressions.py`. `strace -f --seccomp-bpf -e trace=connect` recorded **zero connect syscalls** across the suite and descendants. The test runner used the private HOME/XDG/artifact/temp/config overrides and inherited socket guard, with tree-sitter enabled; no real data or target network was used.
- Offline synthetic suite: `python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py -q --tb=short`, with private HOME/XDG/artifact/tmp roots, socket-blocking `sitecustomize` inherited by subprocesses, pinned tree-sitter dependencies installed from local uv cache into scratch, and `PYTHONPATH` resolving this feature worktree: **634 passed**. This includes flags, successful re-fetch with identical bytes, status/timestamp unknowns, failed refresh, and timestamp preservation.
- First full-suite attempt: 274 failed, 358 passed because the borrowed interpreter lacked pinned parser dependencies. After scratch-only offline installation, 8 guard-induced failures showed the socket guard's `RuntimeError` bypassed normal transport error handling. Changing the guard to `OSError` still prohibits socket connections and yielded the passing suite above. No target network requests were sent.
- `git diff --check` passed. Added-line privacy scan for common private-key/token patterns and selected local paths reported zero matches; this is a bounded scan, not proof of absence of all secrets.
- Independent review of `859f95d2` blocked release: lost updates between inventory writers, replay regression of fetch times, and stale-query errors. Review repairs are now present on the feature branch and need a new independent review. Integration, runtime activation, data import and branch propagation remain parent-owned.
- Fetched `origin/beta` contained both known earlier Hoster and storage-release commits; local `beta` checkout was divergent and was not changed. Repository-local instruction requires features to start at fetched beta; repair propagation to affected descendants/stable must be assessed by integrator rather than performed here.

## Blockers and deferred work

1. **Independent re-review:** inspect the entire repair and rerun the offline synthetic suite, including concurrency, exception/cancellation cleanup, legacy migration and shared-hash replay; required before integration. Trigger: parent assigns independent reviewer.
2. **Existing writers are unsafe:** old active/release writer versions do not enforce this marker and can remove it or falsely advance `last_seen`. This branch alone does not protect data while they run. Integrator must release and verify the corrected code at every writer before reconciliation; test mixed-version replay, old writer rollback/compatibility and complete import fixtures in a coordinated pause.
3. **Historical evidence and migration:** no status or fetch time may be invented. In particular, historical Trello mappings with unknown status must stay unknown; Pinterest first-seen timestamps do not establish successful fetch time. A reviewed importer, complete real-store dry run, fresh verified backups, no-clobber publication/recovery and repeat readback remain necessary. Trigger: all writer versions corrected and owner-authorized coordinated pause. No prior staged migration was applied.
4. **Existing SQLite projections:** migration occurs on the next metadata rebuild, not at deployment; until then old `last_seen` values remain ambiguous. Rebuild from complete metadata under the fenced writer cohort before relying on the new columns. Missing historical metadata cannot recover fetch times.
5. **Runtime and delivery:** feature branch only; no push, merge, Hoster activation, storage reconciliation, or stable propagation. Parent should fetch beta again before review/integration and reconcile if it moved.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/js-cache-freshness`
- **Latest immutable recovery checkpoint before this repair:** `859f95d2be9ef22a296af8a5d469573c6299d302`; review the subsequent feature-branch checkpoint as well.
- **Exact resume point:** independent re-review of the repair checkpoint and tests; no production state touched.
- **Working-tree state at handoff:** expected clean after checkpoint.

## Decision gates

- **Integration:** independent review and focused suite pass; beta re-fetch and ancestry check.
- **Activation / cohort:** verify every writer's deployed revision and compatible behavior before any import; historical data requires separate safe publication procedure.
- **Promotion:** separate owner decision and stable/descendant propagation under lifecycle policy.

## Decision record

- 2026-11-06 — feature constructed on fetched beta; branch checkpoint only, no deployment or data modification.
