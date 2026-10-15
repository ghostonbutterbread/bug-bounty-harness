# Manual-hunter fail-fast note integration dossier

- **Status:** independently approved for beta integration; merged-tree verification pending
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/manual-hunter-fail-fast-note`
- **Worktree:** `/home/ryushe/worktrees/bbh-manual-hunter-fail-fast`
- **Base commit:** `7b899fe0055f419d99ecb9cb94f1e82c3ba6920e`
- **Intended integration target:** `origin/beta` (fetched `2282b68157c1bb627e79f326799ec26266797fee` during work)
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `2495b43` (merge of current `origin/beta` into feature)
- **Feature implementation commit(s):** `82fbb91`
- **Inspiration:** PC-20260914-221118-4041143b; documented File/Description note contract

## Intent and implemented contract

For `--from-file`, parse the note through the same grammar before `ManualHunter` initializes the shared index, storage, context or ledger. A missing File (after existing hint and web-route inference) or any other parser error raises immediately. Valid notes enter the unchanged `ManualHunter.ingest` gate after normal initialization. `parse_text` and watch/interactive/sync callers delegate to the extracted pure parser with resolved family/lane; no alternate validation grammar and no `__new__` escape. No target data or real findings were ingested.

## Evidence and review

- RED: `python -m unittest agents.test_manual_hunter.ManualHunterTests.test_invalid_from_file_fails_before_constructor_side_effects -v` raised `RuntimeError: costly constructor ran` from mocked `load_index` on base.
- GREEN: `python -m unittest agents.test_manual_hunter -q` — 41 tests passed before and after beta reconciliation, including missing-File before index/ledger, valid mocked gate, fallback source-path and API route, and existing isolated real-ingest/dedupe fixture.
- `git diff --check` clean before handoff.
- Independent review of `df0a6bf` against fetched `origin/beta` `2282b68`: approved; all 41 `agents.test_manual_hunter` tests and three targeted fail-fast/fallback/ingest tests passed, `git diff --check` clean. Reviewer made no edits and found no CLI-routing, parser, or ingest-gate regression.
- Merge/ancestry: `2495b43` merges `2282b68` into the feature; `git merge-base --is-ancestor origin/beta HEAD` passed.

## Blockers and deferred work

No blocker for focused local verification. Parent still owns clean beta integration, merged-tree tests, push/read-back, and papercut closure; no runtime activation is implied.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/manual-hunter-fail-fast-note`
- **Latest immutable recovery checkpoint:** `2495b43` (the subsequent dossier-only handoff commit is the current feature tip)
- **Feature implementation commit(s):** `82fbb91`
- **Exact resume point:** integrate reviewed tip in parent-owned clean beta worktree, remove this temporary dossier from beta, run merged-tree suite, push/read back if green.
- **Working-tree state at handoff:** clean after commit expected.

## Decision gates

- **Integration gate:** independent review and focused tests on integration tree.
- **Activation / cohort gate:** not requested.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-15 — reproduced delayed validation with mocked costly constructor; extracted shared pure parser, covered fail-fast and valid gate, no external ingestion.
- 2026-10-15 — independent review approved branch tip `df0a6bf` with 41 passing tests; release awaits merged-tree checks.
