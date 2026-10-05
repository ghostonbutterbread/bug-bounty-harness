# Bunny multi-program integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/bunny-multi-program`
- **Base commit:** `468700b19c3805c8b4c45fe88e3b2b59b4459627`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `feat/bunny-multi-program`
- **Latest immutable recovery checkpoint:** `77ff2289c21e5085848d0602fb0dda802bc0fc6f` (review corrections)
- **Feature implementation commit(s):** `6b546cd52ec2353edf91c0aa16f4e27b441c1339`, `77ff2289c21e5085848d0602fb0dda802bc0fc6f`
- **Inspiration / canonical references:** Discord thread 1556733700027191377; `skills/bunny/SKILL.md`, `skills/bunny-collaborative/SKILL.md`, `skills/bug-goals/SKILL.md`

## Intent

Allow one Bunny coordinator to pursue one goal across named, distinct programs without imposing a breadth quota or moving away from a deep current chain. Preserve collaborative checkpoints and existing program-specific safety boundaries.

## Implemented contract

Explicit `Bunny multi` and `/goal bunny multi` select a collaborative portfolio overlay; maximum three active subagents across all programs. One worker stays within one program but may cover that program's multiple domains. The coordinator keeps a small run-local queue key in the existing campaign record, not per-program Shared. Queue entry does not imply rotation, timer, or negative conclusion. The existing single-program `goal_router.py` is called separately per program; this change adds no standalone CLI runner or live target action.

## Evidence and review

- Tests and commands: `python3 -m unittest tests.test_bunny_skill tests.test_goal_router -v` (7 Bunny tests); `python3 -m pytest -q tests/test_bunny_skill.py tests/test_goal_router.py` (13 passed); `python3 scripts/goal_router.py plan --program sample-one --objective 'Find an ATO in password reset' --class auth` (single-program focused-surface plan); frontmatter/route assertions for Bunny and bug-goals; `git diff --check` clean.
- Policy alignment: compared `bunny` with `bunny-collaborative`, `bug-goals`, `goal_router.py`, registry, and `agents/index.md`. Coordinator queue lives only in existing campaign record; published rules and program-specific evidence remain authoritative. No duplicate router implementation.
- Independent review: first pass held beta integration on multi-worker accounting, parent-mode routing, and stale handoff; corrections included in this follow-up. Fresh verdict pending.
- Replay/cohort/fixture evidence: not applicable (guidance-only change).
- Merge/ancestry evidence: pending.

## Blockers and deferred work

None known. No program-selected live smoke is part of this guidance-only change; a future operator-led goal run can exercise checkpoint queueing with authorized programs.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/bunny-multi-program`
- **Latest immutable recovery checkpoint:** `77ff2289c21e5085848d0602fb0dda802bc0fc6f` (review corrections)
- **Feature implementation commit(s):** `6b546cd52ec2353edf91c0aa16f4e27b441c1339`, `77ff2289c21e5085848d0602fb0dda802bc0fc6f`
- **Exact resume point:** obtain fresh independent review of the corrected commit, then beta integration.
- **Working-tree state at handoff:** clean after dossier-only handoff commit (verify with Git).

## Decision gates

- **Integration gate:** focused tests, lint, independent review of scope/queue semantics.
- **Activation / cohort gate:** after beta integration verify the projected Bunny and bug-goals skills; no unattended runner.
- **Promotion gate:** do not promote to main without explicit direction.

## Decision record

- 2026-10-05 — created explicit multi-program guidance in existing Bunny owner and `/goal` route; no new parallel skill or store.
- 2026-10-05 — first independent review identified three blockers; corrected global active-run accounting and single-parent routing, and refreshed branch handoff.
