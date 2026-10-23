# JS coverage-first repair integration dossier

- **Status:** feature (not merged)
- **Last updated:** 2026-10-23
- **Owner:** t_b317a8e8
- **Branch:** `fix/js-coverage-first-tb317a8e8`
- **Base commit:** `720e3e2ca8960837d891c3bfdc44396c63c139ef` fetched `origin/beta`
- **Intended integration target:** local `beta` (parent handles integration; no push)
- **Owning feature branch/ref:** `fix/js-coverage-first-tb317a8e8`
- **Latest immutable recovery checkpoint:** `8c0667d21e4160a6f6096560e0922dd8921c7072` (implementation `cb311e1`; integration still blocked)
- **Feature implementation commit(s):** `f734ec1`, `edbbd5b`, `cb311e1`
- **Reconciled fetched beta:** `218e86bcad37e6788cb8ecb326bb731afff81efa` via merge `8c0667d` (local beta unchanged)

## Intent and implemented contract

Remove the fixed 45-second parser deadline and isolate every comment scan under a 1 GiB address-space fence and lower CPU scheduling priority; cancellation terminates its child. The optional explicit byte cap remains. Bundle network reads now use bounded chunks and an operator-adjustable per-bundle RAM bound with an explicit pending pause; URL writes preflight the configured 5 GiB floor against actual artifact size and roll back in-memory URL state to the last checkpoint on pressure. Failed URLs remain local until successful publication; shared library rows are keyed against the durable sink on resume. Unchanged module/map budgets pause with an action rather than retrying indefinitely. Endpoint and parameter seed list caps were removed; inline body and map limits are counted as partial coverage. No live target requests were made.

## Evidence and review

- Latest fetched beta merge `8c0667d`; `.venv/bin/python -m pytest agents/test_js_analyzer.py agents/test_js_analyzer_wayback.py -q --tb=short` → 546 passed after that merge; `git diff --check` clean. New regressions cover failed resume publication, paused unchanged budget, per-write floor, bounded bundle read and uncapped endpoint/parameter seeds.
- New local fixtures cover >8 MiB grammar scan, URL-limit resume and failed-attempt bound, disk-floor pause, retry after empty fetch, and interrupt before checkpoint commit.
- Fetched `origin/beta` `218e86b` merged into this branch without conflict; no integration or push.

## Blockers and deferred work

- Whole-state checkpoint serialization and the final shared library/index rebuild are still proportional to accumulated run/library size; large URL sets need incremental state before production-scale claims. The shared library append is sink-deduped per run/URL but not an atomic multi-file transaction; torn rows are repaired at append. Concurrent writers require coordination.
- Final index/SQLite/manifest publication runs from a reserved post-loop margin rather than a fully size-reserved floor, so extremely large final derived outputs can still cross the 5 GiB floor. This is a release residual, not a fully closed disk guarantee.
- Source-map JSON unpacking still uses `json.loads`; 64 MiB map default and module packet budgets are explicit partial states. In-memory bundle threshold pauses rather than streaming analysis of arbitrarily large bundles; operator must raise `--bundle-max-bytes` after RAM review.
- Page collection during resume is repeated before input ID verification; prefer `--input` for durable offline reconstruction. Inline page URLs cannot currently resume without refetching the page.

## Interruption / resume handoff

- **Owning branch:** `fix/js-coverage-first-tb317a8e8`
- **Latest immutable recovery checkpoint:** `8c0667d21e4160a6f6096560e0922dd8921c7072` (implementation `cb311e1`; a dossier-only handoff commit follows).
- **Exact resume point:** parent review of the release residuals before any integration; no feature integration or push performed.
- **Working tree:** clean after dossier handoff commit.

## Decision gates

- **Integration:** parent reviews diff and accepts/defer residuals; do not merge or push from this subagent.
- **Activation:** explicit beta integration and runtime selection.
- **Promotion:** separate stable acceptance.
