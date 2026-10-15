# XSS mapper socket cleanup integration dossier

- **Status:** blocked (independent code review accepted; integration worktree unavailable)
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/xss-mapper-server-cleanup`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-mapper-server-cleanup`
- **Base commit:** `de82c81bb455e459888c20370ad1d61a84f59368` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-15
- **Latest immutable recovery checkpoint:** `1bf5481208ff22465e8150d382fbb42ce75adb5b`
- **Feature implementation commits:** `1bf5481208ff22465e8150d382fbb42ce75adb5b`
- **Inspiration:** `PC-20261015-210009-f38fc5d1` in the shared papercut record.

## Intent and contract

Four XSS mapper HTTPServer fixtures shut down their serving threads but leave listening sockets open. Close each server after shutdown and thread join. No application behavior or live target routing changes.

## Evidence and review

- Before: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q -W error::ResourceWarning` → 15 passed, four PytestUnraisableExceptionWarning instances from unclosed sockets.
- After: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q -W error::ResourceWarning -W error::pytest.PytestUnraisableExceptionWarning` → 15 passed, zero warnings.
- `git diff --check` → clean.
- Independent review (fresh reviewer): accepted the four `server.server_close()` additions after shutdown/join. They close the listening sockets in each fixture's `finally` without changing production behavior or relying on a machine-specific path. Reran `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q -W error::ResourceWarning -W error::pytest.PytestUnraisableExceptionWarning` → 15 passed in 3.82s; `git diff --check de82c81 HEAD` clean.
- Merge/ancestry: fetched `origin beta` again; `origin/beta` remains `de82c81bb455e459888c20370ad1d61a84f59368`, with only implementation commit `1bf5481208ff22465e8150d382fbb42ce75adb5b` unique on feature. No merge or push performed.

## Blockers and deferred work

- **Missing evidence:** merged-tree warning-as-error test and remote beta read-back.
- **Command:** `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q -W error::ResourceWarning -W error::pytest.PytestUnraisableExceptionWarning` from clean beta worktree; fetch/read back `origin/beta` after push.
- **Trigger:** owner makes the local `beta` integration worktree clean and current or explicitly arranges a clean named-beta worktree without disturbing unrelated state.
- **Why blocked:** `beta` is checked out at `/home/ryushe/projects/bug_bounty_harness`, which is 53 commits behind `origin/beta` and has multiple unrelated untracked directories. A nested `bbh-beta-integration/` is detached HEAD and unregistered, not the named beta worktree. Do not clean/reset or change the shared checkout to bypass the gate.
- **Next step:** establish a clean current beta integration worktree, merge the reviewed feature, remove this dossier from beta, rerun focused checks, and push/read back `origin beta` only if all gates pass. Papercut closure remains with parent.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/xss-mapper-server-cleanup`
- **Latest immutable recovery checkpoint:** `1bf5481208ff22465e8150d382fbb42ce75adb5b`
- **Feature implementation commits:** `1bf5481208ff22465e8150d382fbb42ce75adb5b`
- **Exact resume point:** arrange a clean named-`beta` integration worktree without disturbing the shared dirty checkout; fetch and reconcile `origin/beta`, merge feature, remove dossier from integration target, rerun focused test and push/read back only if gates pass. Parent owns papercut closure.
- **Working-tree state at handoff:** clean after the dossier-only review checkpoint commit.

## Decision gates

- **Integration:** code review and focused warning-as-error test passed; blocked by non-clean, stale named-beta worktree. No integration authorized under present checkout state.
- **Activation:** not applicable; test-only change.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-10-15 — reproduced and patched the four socket leaks; implementation committed as `1bf5481208ff22465e8150d382fbb42ce75adb5b`.
- 2026-10-15 — independent review accepted the portable test-only fix and reran all 15 focused tests with warnings treated as errors; release blocked at dirty/stale beta integration worktree. No merged-tree test or push; no outstanding deferred test beyond integration verification above.
