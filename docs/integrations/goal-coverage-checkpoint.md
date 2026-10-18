# Goal-only Coverage checkpoint integration dossier

- **Status:** feature under independent review and local agent evaluation
- **Owner:** Hermes Agent
- **Branch / owning ref:** `feat/goal-coverage-checkpoint-t4c8370c7`
- **Base commit:** `646adb4c9fb15db4a5b978dd11dbb96b32dbc8d8` (`origin/beta` at branch creation)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-18
- **Latest immutable recovery checkpoint:** none yet (commit pending)
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `skills/bug-goals`, `scripts/goal_router.py`, `skills/coverage`, `agents/surface_coverage.py`; LaunchDarkly hunt audit and controlled read-only Coverage-card comparison.

## Intent

Limit the Coverage continuation habit to explicit long-standing goal runs, solo or coordinated. Make missing/thin inventory and exact blocked/unassessed paths visible at pivots and negative closure; do not slow ordinary interactive work, infer exhaustive assessment from archived URLs, or claim that a negative hunt achieved a find-goal.

## Implemented contract

- The explicit `plan` routes `/coverage` and a parent checkpoint contract; `init` remains routing-only.
- New `checkpoint` command reads the existing lane-local Coverage brief, retains bounded question summaries, counts, next-page cursor, inventory-state missing/empty/mapped, source pointers provided by the parent, a selected decision and next/wake action in a run-local receipt and last-state field.
- `bounded-stop` always reports `paused_bounded`, never `eligible_goal_complete`; unresolved or missing Coverage requires named residuals. A host filter cannot hide sibling hosts for a class-wide negative stop. No target traffic, Coverage assessment write, or external goal completion hook is performed.
- Bug Goals owns the goal-only trigger; Hunter Loop/Bunny point their explicit-goal parents to the same checkpoint. Coverage remains the assessment/inventory owner and specialist skills choose techniques.

## Evidence and review

- TDD red: four goal tests failed with missing route/checkpoint; then the bounded-stop negative test failed because an inventory pointer could hide unassessed questions.
- Green: `PYTHONPATH=$PWD python -m pytest tests/test_goal_router.py agents/test_surface_coverage.py agents/test_coverage_cli.py -q` — 48 passed, 12 subtests passed; `git diff --check` passed.
- Local paired parent-agent simulation: pending; isolated fictional fixtures under task scratch, same evidence per arm, baseline beta plan versus feature plan.
- Independent review: pending.
- Current beta compatibility / merge evidence: pending fresh fetch and preflight.

## Blockers and deferred work

- **External completion enforcement:** BBH `goal_router.py` has no `goal_complete` operation. A read-only architecture lookup is pending for the installed goal harness's actual completion path. Until that integration is reviewed, this change records and instructs the parent; it cannot technically block a bypassing caller. Do not claim a hard gate or production activation from this branch alone.
- **Inventory completeness:** Coverage brief only contains registered questions; source artifact references come from the parent, not automatic cross-corpus ingestion. Missing ledger remains a mapping gap; no auto-discovery or percentage is promised.
- **Agent-evaluation decision quality:** six-agent previous frontier comparison was inconclusive. This new goal contract needs matched local parent decisions and later actual installed-runtime validation before any activation claim.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/goal-coverage-checkpoint-t4c8370c7`
- **Latest immutable recovery checkpoint:** none yet (commit pending)
- **Feature implementation commit(s):** none yet
- **Exact resume point:** finish independent review and matched agent simulation, reconcile completion-hook lookup, then decide beta integration separately from runtime activation.
- **Working-tree state at handoff:** task-owned edits pending first verified commit.

## Decision gates

- **Integration gate:** independent review of exact implementation and tests; updated beta reconciliation and integrated tests.
- **Activation / cohort gate:** runtime source and loaded goal skills verified; local simulation is not real goal-run proof.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-18 — isolated feature branched from fetched beta; implemented TDD goal-only checkpoint and source-scoped guidance; awaiting independent review and local agent comparison.
