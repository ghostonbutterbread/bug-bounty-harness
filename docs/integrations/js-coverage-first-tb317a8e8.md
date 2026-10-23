# JS coverage-first repair integration dossier

- **Status:** feature (not merged)
- **Last updated:** 2026-10-23
- **Owner:** t_b317a8e8
- **Branch:** `fix/js-coverage-first-tb317a8e8`
- **Base commit:** `720e3e2ca8960837d891c3bfdc44396c63c139ef` fetched `origin/beta`
- **Intended integration target:** local `beta` (parent handles integration; no push)
- **Owning feature branch/ref:** `fix/js-coverage-first-tb317a8e8`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet

## Intent and implemented contract

Remove the default 8 MiB source-map comment parse cutoff while retaining grammar-aware full-bundle comment selection. Above 8 MiB the tree-sitter parse runs in an isolated worker with 1 GiB address-space and 45-second per-parse wall clock fence; failure is explicit, not absence. The optional explicit byte cap remains. Inventory declares the original normalized URL set, a stable ordered SHA-256 input ID, succeeded/retryable_failed/pending states and a configured 5 GiB disk floor. Per-URL atomic checkpoints permit resume with the same input/order/run/roots; a limit or low disk pauses with pending URLs, not completion. No live target requests were made in verification.

## Evidence and review

- Focused tests: `.venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py -q --tb=short` → 529 passed before local beta reconciliation.
- New local fixtures cover >8 MiB grammar scan, URL-limit resume, disk-floor pause, retry after empty fetch, and interrupt before checkpoint commit.
- Local beta reconciliation and post-merge focused rerun pending.

## Blockers and deferred work

- Checkpoint snapshot currently serializes accumulated run state once per URL; large URL sets incur quadratic serialization/disk writes. Switch to append-only committed per-URL state before high-volume runs.
- Disk floor is tested before URLs, not before every per-URL artifact write; a single huge artifact may cross the floor. Bounded map downloads and packet budgets still apply; bundle fetch remains unbounded.
- Source-map JSON unpacking still uses `json.loads` and per-module packet budgets; oversized maps are explicit `too_large`, not exhaustively analyzed. Source-map module packet limit remains partial.
- Final shared library append and checkpoint are not one transaction; a crash in that window can duplicate library metadata on resume. Reconcile append idempotence before claiming exactly-once publication.
- Page collection during resume is repeated before input ID verification; prefer `--input` for durable offline reconstruction. Inline page URLs cannot currently resume without refetching the page.

## Interruption / resume handoff

- **Owning branch:** `fix/js-coverage-first-tb317a8e8`
- **Latest immutable recovery checkpoint:** none yet
- **Exact resume point:** complete tests, merge local beta, rerun focused tests, commit dossier and implementation.
- **Working tree:** in progress.

## Decision gates

- **Integration:** parent reviews diff and accepts/defer residuals; do not merge or push from this subagent.
- **Activation:** explicit beta integration and runtime selection.
- **Promotion:** separate stable acceptance.
