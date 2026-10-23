# JS coverage-first repair integration dossier

- **Status:** feature (not merged)
- **Last updated:** 2026-10-23
- **Owner:** t_b317a8e8
- **Branch:** `fix/js-coverage-first-tb317a8e8`
- **Base commit:** `720e3e2ca8960837d891c3bfdc44396c63c139ef` fetched `origin/beta`
- **Intended integration target:** local `beta` (parent handles integration; no push)
- **Owning feature branch/ref:** `fix/js-coverage-first-tb317a8e8`
- **Latest immutable recovery checkpoint:** `8c0667d21e4160a6f6096560e0922dd8921c7072` (earlier implementation `cb311e1`; repair commit follows)
- **Feature implementation commit(s):** `f734ec1`, `edbbd5b`, `cb311e1` plus pending repair commit
- **Fetched beta for final reconciliation:** `6a45a0d5a77a33bf82a174b2c19c46c742f546c5` (merge after repair checkpoint)

## Intent and implemented contract

Remove the fixed 45-second parser deadline and isolate every comment scan under a 1 GiB address-space fence and lower CPU scheduling priority; cancellation terminates its child. The optional explicit byte cap remains. Bundle network reads now use bounded chunks and an operator-adjustable per-bundle RAM bound with an explicit pending pause; URL writes preflight the configured 5 GiB floor against actual artifact size and roll back in-memory URL state to the last checkpoint on pressure. Failed URLs remain local until successful publication; shared library rows are keyed against the durable sink on resume. Unchanged module/map budgets pause with an action rather than retrying indefinitely. Endpoint and parameter seed list caps were removed; inline body and map limits are counted as partial coverage. No live target requests were made.

## Evidence and review

- RED: torn two-hint append resumed with one shared provenance row and no SQLite table; mid-finalization mock at 91 bytes free/90-byte floor returned complete with a 4 KiB manifest. GREEN: both cases and fully-appended/missing-SQLite replay are covered by new fixtures. Initial below-floor checkpoint is now a nonzero pause with no manifest; free space and retry without `--resume` (no checkpoint exists).
- Finalization streams run-local JSONL into atomic sibling files, preserves the configured floor through the ledger, shared append, SQLite, external index, checkpoint, and atomic manifest. A floor failure exits 2 with no new complete manifest; durable URL checkpoint supports `--resume` after mid-finalization pressure. Shared provenance identity uses the SQLite unique tuple and always reconciles SQLite from durable shared rows. No fixed parser deadline was introduced.
- Focused `.venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py -q --tb=short` → 548 passed before latest fetched-beta merge; final receipt follows after reconciliation.

## Blockers and deferred work

- Whole-state checkpoint serialization and shared index reconstruction remain proportional to accumulated run/library size; large URL sets need incremental state before production-scale claims. Shared JSONL append and SQLite are independently recoverable but not a multi-file transaction. Concurrent writers require coordination.
- SQLite uses a conservative preflight allowance and a post-write floor check, not a filesystem quota/reservation against concurrent writers or unexpectedly large SQLite journal growth; no complete manifest is published when the post-check fails.
- Source-map JSON unpacking still uses `json.loads`; 64 MiB map default and module packet budgets are explicit partial states. In-memory bundle threshold pauses rather than streaming analysis of arbitrarily large bundles; operator must raise `--bundle-max-bytes` after RAM review.
- Page collection during resume is repeated before input ID verification; prefer `--input` for durable offline reconstruction. Inline page URLs cannot currently resume without refetching the page.

## Interruption / resume handoff

- **Owning branch:** `fix/js-coverage-first-tb317a8e8`
- **Latest immutable recovery checkpoint:** pending repair commit (prior `8c0667d21e4160a6f6096560e0922dd8921c7072`).
- **Exact resume point:** merge fetched `origin/beta` into this clean feature branch, rerun focused suite, update this dossier, hand off to parent for independent release review; do not integrate or push.
- **Working tree:** clean after repair checkpoint commit.

## Decision gates

- **Integration:** parent reviews diff and accepts/defer residuals; do not merge or push from this subagent.
- **Activation:** explicit beta integration and runtime selection.
- **Promotion:** separate stable acceptance.
