# Revert broad BBH script-map pointers

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `revert/bbh-script-skill-map`
- **Base commit:** `59e72403600c9e9035081ca32e7ac5c64f3bbd83`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `revert/bbh-script-skill-map`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** User correction in Discord thread 1557064429915340933; prior merge `59e7240`.

## Intent

Undo only the broad skill-to-index pointer maps and root routes added by merge `59e7240`. The user intended concrete, agent-facing script references in relevant skills (including helpers in `agents/`), not generic index pointers. Preserve all pre-existing script records and the earlier XSS map.

## Implemented contract

`git revert -m 1 --no-commit 59e7240` restores the ten changed files to the merge's first-parent contents. No runtime script logic, scope, or test changes beyond removal of the prior task's route regression.

## Evidence and review

- Tests and commands: `git diff --cached --check` passed; `python3 -m pytest tests/test_script_policy.py -q` returned 25 passed; working-tree comparison against `59e7240^1` for all ten touched paths is empty.
- Independent review: pending.
- Replay/cohort/fixture evidence: Git tree comparison and static policy tests; no live target traffic.
- Merge/ancestry evidence: branch starts from fetched `origin/beta` at `59e7240`.

## Blockers and deferred work

- No revert-specific blocker. Agent-facing script discovery requires a separate, evidence-based mapping of actual scripts and owning skills; do not infer that this revert accomplishes it.

## Interruption / resume handoff

- **Owning feature branch/ref:** `revert/bbh-script-skill-map`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit, independently review, integrate into beta and remove this temporary dossier.
- **Working-tree state at handoff:** staged revert and untracked dossier pending commit.

## Decision gates

- **Integration gate:** exactly prior merge delta reversed; focused tests pass; independent review.
- **Activation / cohort gate:** local BBH beta symlink and source read-back; no remote Hoster deployment.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-06 — user rejected generic pointers; revert staged on isolated branch.
