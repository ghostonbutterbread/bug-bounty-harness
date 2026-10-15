# Manual-hunter fail-fast note integration dossier

- **Status:** feature; awaiting independent review
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/manual-hunter-fail-fast-note`
- **Worktree:** `/home/ryushe/worktrees/bbh-manual-hunter-fail-fast`
- **Base commit:** `7b899fe0055f419d99ecb9cb94f1e82c3ba6920e`
- **Intended integration target:** `origin/beta` (fetched `2282b68157c1bb627e79f326799ec26266797fee` during work)
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none yet; feature tip after commit is the handoff checkpoint
- **Feature implementation commit(s):** pending commit
- **Inspiration:** PC-20260914-221118-4041143b; documented File/Description note contract

## Intent and implemented contract

For `--from-file`, parse the note through the same grammar before `ManualHunter` initializes the shared index, storage, context or ledger. A missing File (after existing hint and web-route inference) or any other parser error raises immediately. Valid notes enter the unchanged `ManualHunter.ingest` gate after normal initialization. `parse_text` and watch/interactive/sync callers delegate to the extracted pure parser with resolved family/lane; no alternate validation grammar and no `__new__` escape. No target data or real findings were ingested.

## Evidence and review

- RED: `python -m unittest agents.test_manual_hunter.ManualHunterTests.test_invalid_from_file_fails_before_constructor_side_effects -v` raised `RuntimeError: costly constructor ran` from mocked `load_index` on base.
- GREEN: `python -m unittest agents.test_manual_hunter -q` — 41 tests passed, including missing-File before index/ledger, valid mocked gate, fallback source-path and API route, and existing isolated real-ingest/dedupe fixture.
- `git diff --check` clean before handoff.
- Independent review: pending parent.
- Merge/ancestry: origin/beta advanced only in Chromium guidance files; reconcile to `2282b68` before handoff commit.

## Blockers and deferred work

No blocker for focused local verification. Independent release review and integration intentionally owned by parent; no push, papercut close, or runtime activation here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/manual-hunter-fail-fast-note`
- **Latest immutable recovery checkpoint:** feature tip after commit
- **Feature implementation commit(s):** pending
- **Exact resume point:** review diff and test receipt, then integrate in parent-owned beta worktree if accepted.
- **Working-tree state at handoff:** clean after commit expected.

## Decision gates

- **Integration gate:** independent review and focused tests on integration tree.
- **Activation / cohort gate:** not requested.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-15 — reproduced delayed validation with mocked costly constructor; extracted shared pure parser, covered fail-fast and valid gate, no external ingestion.
