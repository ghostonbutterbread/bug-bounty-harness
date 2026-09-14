# Scope puller out-of-scope and Intigriti integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `feat/scope-puller-outscope-intigriti`
- **Base commit:** `e0fef5c1fbd90662af53d798d26a1e32e3d00f63`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-14
- **Owning feature branch/ref:** `feat/scope-puller-outscope-intigriti`
- **Latest immutable recovery checkpoint:** `b1849bc49baac3fa0542ee679e15592ee544af4e`
- **Feature implementation commit(s):** `b14b47f58681985bc63969e5f7ac9856aad44c82`, `b1849bc49baac3fa0542ee679e15592ee544af4e`
- **Inspiration / canonical references:** Discord thread `1549123711834267729`; public Intigriti rendered program page.

## Intent

Persist structured out-of-scope targets alongside pulled in-scope scope files, and support public web-page pulls from Intigriti without an authenticated API. Preserve HackerOne and Bugcrowd behavior.

## Implemented contract

The puller will write canonical and legacy `out-of-scope.txt` files with metadata annotations understood by `ScopeValidator`; parse public Intigriti rendered asset cards into in-scope assets and explicit exclusions; and preserve the fetched Intigriti HTML as raw evidence. This is a parser for currently rendered public pages, not an API implementation or authorization to test.

## Evidence and review

- Tests and commands: `PYTHONPATH=<worktree> python3 -m pytest agents/test_scope_puller_seed_files.py agents/test_scope_validator.py agents/test_scope_manager.py agents/test_scope_seed_files.py -q` (122 passed); `python3 -m compileall -q agents/scope_puller.py`; `git diff --check`; read-only live parse of the public Intigriti program page found 3 domains, 2 URLs, and 16 exclusions.
- Independent review: the first review blocked the shorthand URL issue; the focused repair was re-reviewed; and final metadata review approved `41a8f9ceee9c51d0b9c4dff645d9ca4819486563` with 122 isolated tests passing.
- Replay/cohort/fixture evidence: fixture tests cover rendered in/out-of-scope cards, shorthand URL resolution/saving, and canonical/legacy file persistence.
- Merge/ancestry evidence: feature is descended from `e0fef5c1fbd90662af53d798d26a1e32e3d00f63`; beta was refreshed at that same clean tip before integration.

## Blockers and deferred work

- **Missing test or evidence:** none before beta merge.
- **Command / fixture / environment needed:** beta merge preflight in the clean integration worktree.
- **Trigger to run it:** now.
- **Why it blocks integration, activation, or promotion:** merge compatibility must be demonstrated against the refreshed beta tip.
- **Next completion step / successor reference:** perform the beta merge preflight, then intentionally merge and remove this dossier from beta.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/scope-puller-outscope-intigriti`
- **Latest immutable recovery checkpoint:** `b1849bc49baac3fa0542ee679e15592ee544af4e`; `df9e167703a65325fb8d72554da22958ad2a1600` is the prior dossier-only checkpoint, and the current branch tip contains this later dossier-only handoff commit.
- **Feature implementation commit(s):** `b14b47f58681985bc63969e5f7ac9856aad44c82`, `b1849bc49baac3fa0542ee679e15592ee544af4e`
- **Exact resume point:** obtain independent review of this current dossier-only handoff and the implementation through `b1849bc49baac3fa0542ee679e15592ee544af4e`, then run the beta merge preflight if accepted.
- **Working-tree state at handoff:** clean after committing this dossier-only handoff.

## Decision gates

- **Integration gate:** isolated tests pass, fresh review is accepted, and the current beta merge preflight is clean.
- **Activation / cohort gate:** no runtime activation; a future pull must use public program data and program rules.
- **Promotion gate:** beta only; main promotion is outside this task.

## Decision record

- 2026-09-14 — implemented fixture-tested scope persistence and public Intigriti parsing; checkpointed at `b14b47f`.
- 2026-09-14 — independent review found and the branch fixed the `owner/program` URL resolution defect at `b1849bc`; second review found only stale dossier metadata.
- 2026-09-14 — final independent metadata review approved `41a8f9c`; prepared this dossier-only review-ready handoff for the clean beta merge preflight.
