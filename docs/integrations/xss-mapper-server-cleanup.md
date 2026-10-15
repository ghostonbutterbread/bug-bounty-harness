# XSS mapper socket cleanup integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/xss-mapper-server-cleanup`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-mapper-server-cleanup`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Inspiration:** `PC-20261015-210009-f38fc5d1` in the shared papercut record.

## Intent and contract

Four XSS mapper HTTPServer fixtures shut down their serving threads but leave listening sockets open. Close each server after shutdown and thread join. No application behavior or live target routing changes.

## Evidence and review

- Before: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q -W error::ResourceWarning` → 15 passed, four PytestUnraisableExceptionWarning instances from unclosed sockets.
- After: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q -W error::ResourceWarning -W error::pytest.PytestUnraisableExceptionWarning` → 15 passed, zero warnings.
- `git diff --check` → clean.
- Independent review: pending.
- Merge/ancestry: feature based on fetched `origin/beta` tip; target integration pending.

## Blockers and deferred work

None for the focused local test. Integration and post-merge verification pending independent review.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/xss-mapper-server-cleanup`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Exact resume point:** commit the tested change, obtain independent review, integrate to clean beta, rerun focused test and close the papercut.
- **Working-tree state:** implementation and dossier uncommitted until checkpoint.

## Decision gates

- **Integration:** focused warning-as-error test and independent diff review, then clean beta merge.
- **Activation:** not applicable; test-only change.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-10-15 — reproduced and patched the four socket leaks; review pending.
