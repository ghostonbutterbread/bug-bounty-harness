# Bunny multi-program integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/bunny-multi-program`
- **Base commit:** `468700b19c3805c8b4c45fe88e3b2b59b4459627`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `feat/bunny-multi-program`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Discord thread 1556733700027191377; `skills/bunny/SKILL.md`, `skills/bunny-collaborative/SKILL.md`, `skills/bug-goals/SKILL.md`

## Intent

Allow one Bunny coordinator to pursue one goal across named, distinct programs without imposing a breadth quota or moving away from a deep current chain. Preserve collaborative checkpoints and existing program-specific safety boundaries.

## Implemented contract

Explicit `Bunny multi` and `/goal bunny multi` select a collaborative portfolio overlay; maximum three active subagents across all programs. One worker stays within one program but may cover that program's multiple domains. The coordinator keeps a small run-local queue key in the existing campaign record, not per-program Shared. Queue entry does not imply rotation, timer, or negative conclusion. The existing single-program `goal_router.py` is called separately per program; this change adds no standalone CLI runner or live target action.

## Evidence and review

- Tests and commands: `python3 -m unittest tests.test_bunny_skill tests.test_goal_router -v` (7 Bunny tests); `python3 -m pytest -q tests/test_bunny_skill.py tests/test_goal_router.py` (13 passed); `python3 scripts/goal_router.py plan --program sample-one --objective 'Find an ATO in password reset' --class auth` (single-program focused-surface plan); frontmatter/route assertions for Bunny and bug-goals; `git diff --check` clean.
- Policy alignment: compared `bunny` with `bunny-collaborative`, `bug-goals`, `goal_router.py`, registry, and `agents/index.md`. Coordinator queue lives only in existing campaign record; published rules and program-specific evidence remain authoritative. No duplicate router implementation.
- Independent review: pending.
- Replay/cohort/fixture evidence: not applicable (guidance-only change).
- Merge/ancestry evidence: pending.

## Blockers and deferred work

None known. No program-selected live smoke is part of this guidance-only change; a future operator-led goal run can exercise checkpoint queueing with authorized programs.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-multi-program`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** run focused checks, independent review, then beta integration.
- **Working-tree state at handoff:** intentionally uncommitted until validation.

## Decision gates

- **Integration gate:** focused tests, lint, independent review of scope/queue semantics.
- **Activation / cohort gate:** after beta integration verify the projected Bunny and bug-goals skills; no unattended runner.
- **Promotion gate:** do not promote to main without explicit direction.

## Decision record

- 2026-10-05 — created explicit multi-program guidance in existing Bunny owner and `/goal` route; no new parallel skill or store.
