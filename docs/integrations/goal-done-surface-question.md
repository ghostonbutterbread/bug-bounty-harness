# Goal-done surface question integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/goal-done-surface-question`
- **Base commit:** `fd095a5891d2a70596ab91eac9d1a0c7331e983f` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-27
- **Owning feature branch/ref:** `fix/goal-done-surface-question`
- **Latest immutable recovery checkpoint:** `dc8f6fe848340d37bdaad768d848c2f1c0ed5519`
- **Feature implementation commit(s):** `dc8f6fe848340d37bdaad768d848c2f1c0ed5519`
- **Inspiration / canonical references:** Ryushe request to put a hunt-goal done question in `bug-goals`, answered by existing surface skills rather than a new checklist.

## Intent

Vulnerability-hunt `/goal` runs were treatable as done when the current path felt finished. Broad goals already asked “is there more to map?” Focused and continuation hunts had an empty completion contract. This branch makes the stop ask whether unexamined surface would still move the objective, and routes that question to existing skills. It does not add a sweep, preload those skills, or change technology-review or revalidation goals.

## Implemented contract

- `skills/bug-goals/SKILL.md` owns the question and the skill edges: `surface-expansion`, `live-map`, `technology-research`, `bypass`/`waf`, `access-control`, `assumption-testing`.
- `scripts/goal_router.py` emits that question on the completion contract for `broad-program`, `focused-surface`, and `continuation`. Broad goals keep the existing mapping reconciliation first.
- The checkpoint text tells a vulnerability-hunt stop to load the owning skill named in the completion contract.
- `docs/goal-runs.md` points at the skill and does not restate the route.
- A warm or hot chain is not interrupted. A locally exhausted lane is not reopened without a new wake condition. Only verified fulfillment completes the goal.

## Evidence and review

- Tests and commands: `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest tests/test_goal_router.py -q` — 25 passed. This worktree has no `.venv`; that command used the sibling checkout interpreter so `bounty_core` could import. The tests themselves ran against this worktree.
- Independent review: pass, `deleg_9e53fe9d`, no findings. Reviewer reran `tests/test_goal_router.py` (25 passed).
- Replay/cohort/fixture evidence: not applicable; no live target
- Merge/ancestry evidence: not merged

## Blockers and deferred work

- **Missing test or evidence:** independent review, then beta integration and runtime activation
- **Command / fixture / environment needed:** review of this branch diff; beta merge only after review
- **Trigger to run it:** implementation commit exists
- **Why it blocks integration, activation, or promotion:** review has not accepted the diff; Hoster projection is not updated
- **Next completion step / successor reference:** independent review, then merge into a current beta worktree if accepted

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/goal-done-surface-question`
- **Latest immutable recovery checkpoint:** `dc8f6fe848340d37bdaad768d848c2f1c0ed5519`
- **Feature implementation commit(s):** `dc8f6fe848340d37bdaad768d848c2f1c0ed5519`
- **Exact resume point:** independent review of `dc8f6fe` against `origin/beta`; do not merge until review accepts
- **Working-tree state at handoff:** clean after the dossier SHA commit

## Decision gates

- **Integration gate:** independent review accepts the diff; merge into current `beta`; do not push `HEAD:beta`
- **Activation / cohort gate:** separate from merge; Hoster skill projection not claimed
- **Promotion gate:** not a stable/`main` change

## Decision record

- 2026-10-27 — independent review `deleg_9e53fe9d` passed with no findings. Beta merge not done.
