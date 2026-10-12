# Cross-class surface coverage integration dossier

- **Status:** feature
- **Owner:** Hermes / Ryushe
- **Branch:** `feat/surface-coverage-index-t31601ec4`
- **Base commit:** `05ad56b7f17dd3d013ce0f76ec6363b307407009` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-12
- **Owning feature branch/ref:** `feat/surface-coverage-index-t31601ec4`
- **Latest immutable recovery checkpoint:** `5b76e9974a144407cb1f9ab8d0774ebe8dab3314`
- **Feature implementation commit(s):** `5b76e9974a144407cb1f9ab8d0774ebe8dab3314`
- **Inspiration / canonical references:** Hoster Hollister XSS agent coverage audit; `agents/coverage_store.py`, `agents/url_ingest.py`, `agents/attempts.py`, and the ledger/MapStore skills.

## Intent

Make mapped-but-untested live surfaces enumerable across vulnerability classes, and make exhaustion specific and evidence-backed. Preserve existing Attempts, static file coverage, URL review, MapStore, private Hypotheses, Leads, and Findings as separate owners. No target traffic or live-data backfill.

## Implemented contract

Implemented: lane-local `ledgers/surface_coverage.sqlite`; stable surface/class identity; explicit discover, assess, bounded brief and assessment history through `me_ledger.py`; mapping provenance and optional fingerprint invalidation; opaque sanitized evidence references, not payload histories. Unclassified mapped surfaces remain countable without assuming every class applies. No automatic status inference from Attempts or findings. Existing `coverage.json` remains static file/snapshot coverage. Agent entry and ledger/XSS/API mapping skills route writers/readers.

## Evidence and review

- Tests and commands: red/green `agents/test_surface_coverage.py` (missing module, CLI, unclassified inventory, attribution and history failures observed); `python3 -m pytest agents/test_surface_coverage.py agents/test_me_ledger.py agents/test_coverage_store.py agents/test_attempts.py agents/test_manual_hunter.py -q` => 82 passed, 26 subtests passed after review repairs. `python3 -m pytest tests/test_script_policy.py -q` => 25 passed. CLI smoke in isolated scratch: discover => one untested row, assess blocked => persisted history with evidence pointer.
- Independent review: first pass requested four repairs: older known fingerprints restoring exhausted, >200 questions not enumerable, partial bulk imports, and common auth-material acceptance. Test-first repairs made for each; re-review pending.
- Replay/cohort/fixture evidence: isolated temporary storage fixtures; no Hoster writes.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- Automatic adapters for each individual mapper output are deferred: mapper schemas differ and imports must not convert source-derived hints to tested claims. Trigger: review one concrete inventory producer and add its adapter with a fixture and provenance test.
- Hoster activation is separate from beta integration. Trigger: explicit lane rollout; verify deployed checkout and a fresh `bbh` consumer before claiming active use.
- Fingerprints are opaque and unordered. Previously observed older versions are rejected, but a never-seen obsolete fingerprint cannot be detected without upstream ordering. Trigger: a mapper that provides an authoritative monotonic version; add a version contract and test before using it to determine freshness.
- Adjacent `agents/test_sync_reports.py` has two canonical report-title assertion failures on both this feature and a clean `origin/beta` worktree at `05ad56b`. They are pre-existing and unrelated to this patch; no report pipeline code changed. Trigger for their repair: a separate report-output defect task. Remaining 57 sync/URL tests pass in this feature worktree.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/surface-coverage-index-t31601ec4`
- **Latest immutable recovery checkpoint:** `5b76e9974a144407cb1f9ab8d0774ebe8dab3314`
- **Feature implementation commit(s):** `5b76e9974a144407cb1f9ab8d0774ebe8dab3314`
- **Exact resume point:** independent review of current diff and tests, then reconcile current beta and integrate if approved.
- **Working-tree state at handoff:** implementation and test-first evidence completed; checkpoint commit precedes review.

## Decision gates

- **Integration gate:** focused tests, CLI smoke, independent review, clean current beta merge.
- **Activation / cohort gate:** explicit deployment and current runtime verification; no live historical backfill by default.
- **Promotion gate:** stable/main only on separate owner direction.

## Decision record

- 2026-10-12 — created isolated feature from fetched beta; chose generic BBH surface/class semantics rather than overloading static-file coverage.
