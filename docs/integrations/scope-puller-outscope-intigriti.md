# Scope puller out-of-scope and Intigriti integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/scope-puller-outscope-intigriti`
- **Base commit:** `e0fef5c1fbd90662af53d798d26a1e32e3d00f63`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-14
- **Owning feature branch/ref:** `feat/scope-puller-outscope-intigriti`
- **Latest immutable recovery checkpoint:** `b14b47f58681985bc63969e5f7ac9856aad44c82`
- **Feature implementation commit(s):** `b14b47f58681985bc63969e5f7ac9856aad44c82`
- **Inspiration / canonical references:** Discord thread `1549123711834267729`; public Intigriti rendered program page.

## Intent

Persist structured out-of-scope targets alongside pulled in-scope scope files, and support public web-page pulls from Intigriti without an authenticated API. Preserve HackerOne and Bugcrowd behavior.

## Implemented contract

The puller will write canonical and legacy `out-of-scope.txt` files with metadata annotations understood by `ScopeValidator`; parse public Intigriti rendered asset cards into in-scope assets and explicit exclusions; and preserve the fetched Intigriti HTML as raw evidence. This is a parser for currently rendered public pages, not an API implementation or authorization to test.

## Evidence and review

- Tests and commands: `PYTHONPATH=<worktree> python3 -m pytest agents/test_scope_puller_seed_files.py agents/test_scope_validator.py -q` (117 passed); `python3 -m compileall -q agents/scope_puller.py`; `git diff --check`; read-only live parse of the public Intigriti program page found 3 domains, 2 URLs, and 16 exclusions.
- Independent review: pending.
- Replay/cohort/fixture evidence: fixture tests cover rendered in/out-of-scope cards and canonical/legacy file persistence.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** independent implementation review.
- **Command / fixture / environment needed:** fresh reviewer in this feature worktree.
- **Trigger to run it:** after implementation commit.
- **Why it blocks integration, activation, or promotion:** material shared scope parsing needs an independent release gate.
- **Next completion step / successor reference:** commit this cohesive change, update this dossier with its SHA, then obtain review.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/scope-puller-outscope-intigriti`
- **Latest immutable recovery checkpoint:** `b14b47f58681985bc63969e5f7ac9856aad44c82`
- **Feature implementation commit(s):** `b14b47f58681985bc63969e5f7ac9856aad44c82`
- **Exact resume point:** request independent review of `b14b47f58681985bc63969e5f7ac9856aad44c82`, then merge to beta if accepted.
- **Working-tree state at handoff:** intentionally uncommitted (dossier checkpoint update only).

## Decision gates

- **Integration gate:** isolated tests pass, fresh review is accepted, and the current beta merge preflight is clean.
- **Activation / cohort gate:** no runtime activation; a future pull must use public program data and program rules.
- **Promotion gate:** beta only; main promotion is outside this task.

## Decision record

- 2026-09-14 — implemented fixture-tested scope persistence and public Intigriti parsing; awaiting checkpoint and review.
