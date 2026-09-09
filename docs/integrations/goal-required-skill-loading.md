# Goal routed-skill loading integration dossier

- **Status:** reviewed and behaviorally verified; ready for beta integration
- **Owner:** Hermes
- **Branch:** `docs/goal-required-skill-loading`
- **Base commit:** `dfc5989466af3dbdca65493ce865ccc26ca18052`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-09
- **Owning task:** `t_b7a1a459`
- **Implementation commit:** `c5ab75cd1bc74dc4369df123bec2c87b676aea08`

## Intent

Prevent an explicit `/goal` run from treating the `bug-goals` wrapper or its generated plan as a substitute for the safety, mode-owner, mapping, memory, and specialist skills selected by that route.

## Implemented contract

`bug-goals` now explicitly requires an agent to load each applicable routed skill before acting on the portion of the goal it governs. Conditional specialist skills load when their trigger applies rather than all possible classes being preloaded.

## Evidence and review

- Focused source: `skills/bug-goals/SKILL.md`
- Verification: `uv run --with pytest python -m pytest tests/test_goal_router.py -q` → 6 passed.
- Planner smoke: `python3 scripts/goal_router.py plan --program example --objective 'Find a new vulnerability'` resolved to `broad-program` with 9 routes; `python3 scripts/goal_router.py plan --program example --objective 'Review the creative editor workflow' --url https://app.example/creative` resolved to `focused-surface` with 6 routes.
- `git diff --check` passed.
- Independent review: approved with no blocking findings after the incorrect full implementation SHA was corrected in `cae09008ede024965188dedb4c24850ee5eca9d1`.
- Clean agent routing smoke: `deleg_6e660158` received only the PortSwigger Academy goal, feature skill reference, and stop-before-live-action boundary. Its transcript records actual loads of the routed security, live-testing, mapping, memory, hypothesis, browser-session, and Chromium skills without an evaluator-provided expected-skill list.
- Smoke boundary: no target request, browser launch, credential access, mutation, lab selection, or solution attempt occurred.
- Residual environment issue: an unqualified `bug-goals` resolver call encountered the pre-existing duplicate-name ambiguity, then recovered through the categorized skill path; this did not prevent the routed loads and is tracked separately.

## Boundaries

- No change to goal modes, depth cadence, mapping completion contracts, orchestration, or browser behavior.
- No requirement to preload every skill returned by the router.
- No activation, merge, or push is implied by this feature branch.

## Interruption / resume handoff

- **Current checkpoint:** implementation committed at `c5ab75cd1bc74dc4369df123bec2c87b676aea08`; the branch tip contains later dossier-only handoff/remediation commits.
- **Exact resume point:** integrate the reviewed branch into a clean current local `beta`, remove this temporary dossier from the integration target, rerun focused checks from beta, and verify the active skill projection. Do not push without separate direction.
