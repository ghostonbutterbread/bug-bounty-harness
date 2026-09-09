# Goal routed-skill loading integration dossier

- **Status:** implementation complete; review pending
- **Owner:** Hermes
- **Branch:** `docs/goal-required-skill-loading`
- **Base commit:** `dfc5989466af3dbdca65493ce865ccc26ca18052`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-09
- **Owning task:** `t_b7a1a459`

## Intent

Prevent an explicit `/goal` run from treating the `bug-goals` wrapper or its generated plan as a substitute for the safety, mode-owner, mapping, memory, and specialist skills selected by that route.

## Implemented contract

`bug-goals` now explicitly requires an agent to load each applicable routed skill before acting on the portion of the goal it governs. Conditional specialist skills load when their trigger applies rather than all possible classes being preloaded.

## Evidence and review

- Focused source: `skills/bug-goals/SKILL.md`
- Verification: `uv run --with pytest python -m pytest tests/test_goal_router.py -q` → 6 passed.
- Planner smoke: broad objective resolved to `broad-program` with 9 routes; focused creative objective resolved to `focused-surface` with 6 routes.
- `git diff --check` passed.
- Independent review: pending.
- Live target interaction: none.

## Boundaries

- No change to goal modes, depth cadence, mapping completion contracts, orchestration, or browser behavior.
- No requirement to preload every skill returned by the router.
- No activation, merge, or push is implied by this feature branch.

## Interruption / resume handoff

- **Current checkpoint:** uncommitted implementation in the named worktree.
- **Exact resume point:** run proportional validation, commit the isolated change, request independent review, and reconcile only concrete findings before proposing beta integration.
