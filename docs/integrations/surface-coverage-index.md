# Cross-class surface coverage integration dossier

- **Status:** isolated for design refinement; not active on beta
- **Owner:** Hermes / Ryushe
- **Branch:** `feat/surface-coverage-index-t31601ec4`
- **Base commit:** `05ad56b7f17dd3d013ce0f76ec6363b307407009` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-12 PDT
- **Owning feature branch/ref:** `feat/surface-coverage-index-t31601ec4`
- **Latest immutable recovery checkpoint:** `26c2a372265f95f91226ad8371b01d85632c9f09`
- **Feature implementation commit(s):** `5b76e9974a144407cb1f9ab8d0774ebe8dab3314`, `f2c853e8b181b5410739e0acdf0b105ab5634e4c`, `26c2a372265f95f91226ad8371b01d85632c9f09`
- **Inspiration / canonical references:** Hoster Hollister XSS agent coverage audit; `agents/coverage_store.py`, `agents/url_ingest.py`, `agents/attempts.py`, and the ledger/MapStore skills.

## Intent

Make mapped-but-untested live surfaces enumerable across vulnerability classes, and make exhaustion specific and evidence-backed. Preserve existing Attempts, static file coverage, URL review, MapStore, private Hypotheses, Leads, and Findings as separate owners. No target traffic or live-data backfill.

## Implemented contract

Implemented: lane-local `ledgers/surface_coverage.sqlite`; stable surface/class identity; explicit discover, assess, bounded brief and assessment history through `me_ledger.py`; mapping provenance and optional fingerprint invalidation; opaque sanitized evidence references, not payload histories. Unclassified mapped surfaces remain countable without assuming every class applies. No automatic status inference from Attempts or findings. Existing `coverage.json` remains static file/snapshot coverage. Agent entry and ledger/XSS/API mapping skills route writers/readers.

## Evidence and review

- Tests and commands: red/green `agents/test_surface_coverage.py` (initial contract and each review repair); `python3 -m pytest agents/test_surface_coverage.py agents/test_me_ledger.py agents/test_coverage_store.py agents/test_attempts.py agents/test_manual_hunter.py tests/test_script_policy.py -q` => 108 passed, 30 subtests passed. CLI smoke in isolated scratch: discover => one untested row, assess blocked => persisted history with evidence pointer; the CLI assessment now requires the observed `--expected-fingerprint`.
- Independent review: first pass requested four repairs: older known fingerprints restoring exhausted, >200 questions not enumerable, partial bulk imports, and common auth-material acceptance. Re-review verified those cases but found a stale-assessment race (no caller-supplied fingerprint) and further named secret patterns. Final independent re-review approved the fingerprint fence and secret checks; no actionable code blocker. Reviewer reran 108 tests / 30 subtests and security-reporting skill tests (6 passed / 50 subtests).
- Replay/cohort/fixture evidence: isolated temporary storage fixtures; no Hoster writes.
- Merge/ancestry evidence: previously merged as `cfdc9ddf0d54516e3bd369b6d8edb72ae024a4c1`; operator requested isolation before fine-tuning. Local beta reverted that merge at `9f31d8bbc963fa404d1ec2350074244062dd88cb` after newer Bunny work was fast-forwarded. Publication/read-back is a separate gate; this feature branch retains the complete implementation.

## Blockers and deferred work

- Automatic adapters for each individual mapper output are deferred: mapper schemas differ and imports must not convert source-derived hints to tested claims. Trigger: review one concrete inventory producer and add its adapter with a fixture and provenance test.
- Adoption and cross-store reconciliation are unproven: written instructions alone do not guarantee agents register every mapped surface or assess at pivot/handoff. Before reintegration, choose one real mapper and one specialist run; reconcile mapper rows, Attempts/MapStore references, coverage state and handoff, including interrupted and concurrent writers. Preserve each existing store as its owner; avoid automatic exhaustion from Attempts/findings.
- The original feature is already a parent of the reverted beta merge. Merging this unchanged branch again will not restore the code; after refinement, integrate explicit new changes and deliberately revert the beta rollback (or carry an equivalent reviewed patch), then test the resulting tree. Do not reset or rewrite beta history.
- Hoster activation is separate from beta integration. Trigger: explicit lane rollout; verify deployed checkout and a fresh `bbh` consumer before claiming active use.
- Fingerprints are opaque and unordered. Previously observed older versions are rejected, but a never-seen obsolete fingerprint cannot be detected without upstream ordering. Trigger: a mapper that provides an authoritative monotonic version; add a version contract and test before using it to determine freshness.
- Adjacent `agents/test_sync_reports.py` has two canonical report-title assertion failures on both this feature and a clean `origin/beta` worktree at `05ad56b`. They are pre-existing and unrelated to this patch; no report pipeline code changed. Trigger for their repair: a separate report-output defect task. Remaining 57 sync/URL tests pass in this feature worktree.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/surface-coverage-index-t31601ec4`
- **Latest immutable recovery checkpoint:** `26c2a372265f95f91226ad8371b01d85632c9f09`
- **Feature implementation commit(s):** `5b76e9974a144407cb1f9ab8d0774ebe8dab3314`, `f2c853e8b181b5410739e0acdf0b105ab5634e4c`, `26c2a372265f95f91226ad8371b01d85632c9f09`
- **Exact resume point:** refine the store boundaries, agent-use triggers, and cross-store reconciliation with Ryushe; add concrete integration tests/adapters on this branch. Rebase is not authorized; reconcile with then-current beta before any separately approved reintegration.
- **Working-tree state at handoff:** branch preserves reviewed implementation and tests. No Hoster activation or historical backfill.

## Decision gates

- **Integration gate:** owner approves the refined contract, one mapper→agent→evidence/handoff exercise passes, focused and adjacent tests pass, independent re-review, clean current beta merge.
- **Activation / cohort gate:** explicit deployment and current runtime verification; no live historical backfill by default.
- **Promotion gate:** stable/main only on separate owner direction.

## Decision record

- 2026-10-12 — created isolated feature from fetched beta; chose generic BBH surface/class semantics rather than overloading static-file coverage.
- 2026-10-12 — independent re-review approved the reviewed feature after two test-first repair rounds. Accept for beta only; no Hoster activation or stable promotion. Unordered unseen fingerprints remain an explicit mapper-version limitation; the assessed version is now compared at write time.
- 2026-10-12 PDT — Ryushe requested this large change remain in its own branch while store ownership and adoption are fine-tuned. Revert the beta integration without rewriting history; previous review is retained as code evidence, not permission to remerge before new acceptance criteria.
