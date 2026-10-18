# Goal-only Coverage checkpoint integration dossier

- **Status:** second review class-identity blocker repaired; fresh independent review pending
- **Owner:** Hermes Agent
- **Branch / owning ref:** `feat/goal-coverage-checkpoint-t4c8370c7`
- **Base commit:** `646adb4c9fb15db4a5b978dd11dbb96b32dbc8d8` (`origin/beta` at branch creation)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-18
- **Latest immutable recovery checkpoint:** `42e5a4c3b136240ff579c02f5c2b0f73cc4a0891` (class-identity implementation; check later handoff-only tip separately)
- **Feature implementation commit(s):** `af8e8670992de298de66cff50765d69df7d7d48b`, `8256a1e4f2ef43c3b5d2d2a31cdc83fcb2dddc08`, `42e5a4c3b136240ff579c02f5c2b0f73cc4a0891`
- **Inspiration / canonical references:** `skills/bug-goals`, `scripts/goal_router.py`, `skills/coverage`, `agents/surface_coverage.py`; LaunchDarkly hunt audit and controlled read-only Coverage-card comparison.

## Intent

Limit the Coverage continuation habit to explicit long-standing goal runs, solo or coordinated. Make missing/thin inventory and exact blocked/unassessed paths visible at pivots and negative closure; do not slow ordinary interactive work, infer exhaustive assessment from archived URLs, or claim that a negative hunt achieved a find-goal.

## Implemented contract

- The explicit `plan` routes `/coverage` and a parent checkpoint contract; `init` remains routing-only.
- New `checkpoint` command reads the existing lane-local Coverage brief, retains bounded question summaries including `(surface_id,class_name)` identity, counts, next-page cursor, inventory-state missing/empty/no-matching/mapped, source pointers provided by the parent, a selected decision and next/wake action in one atomic run-local state history.
- `bounded-stop` always reports `paused_bounded`, never `eligible_goal_complete`; unresolved or missing Coverage requires named residuals. A negative stop cannot hide sibling hosts or, for a broad goal, other classes. No target traffic, Coverage assessment write, or external goal completion hook is performed.
- Bug Goals owns the goal-only trigger; Hunter Loop/Bunny point their explicit-goal parents to the same checkpoint. Coverage remains the assessment/inventory owner and specialist skills choose techniques.

## Evidence and review

- TDD red: four goal tests failed with missing route/checkpoint; then the bounded-stop negative test failed because an inventory pointer could hide unassessed questions.
- Green: `PYTHONPATH=$PWD python -m pytest tests/test_goal_router.py agents/test_surface_coverage.py agents/test_coverage_cli.py -q` — 55 passed, 12 subtests passed after second repair; `git diff --check` passed. CLI `checkpoint` read the fictional blocked/unassessed fixture without target activity.
- Local paired parent-agent simulation: four fresh read-only agents, two matched prompts (solo missing Coverage and coordinator mapped Coverage). Control/feature evidence was SHA-256-identical per pair. All four rejected XSS goal completion and chose the unrendered context-list consumer; feature more explicitly called the missing ledger a mapping gap. No demonstrated decision-quality uplift; natural installed skill/CLI discovery was not tested.
- Independent first review blocked `af8e867` on filtered negative stops, misleading `empty` for filtered views, and dual-write receipt failure. Focused regressions now reject a negative stop with any host filter or class filter for a broad goal; distinguish absent/empty/no matching ledger; use one atomic state history and clean temporary files on failure. Fresh independent review required on the repair tip.
- Independent second review of `8bae10f` verified those fixes but blocked on a broad-goal receipt conflating two vulnerability-class questions with one surface ID. A failing same-surface XSS+IDOR test preceded adding `class_name` to each bounded item. Fresh independent review required.
- Current beta compatibility / merge evidence: pending fresh fetch and preflight.

## Blockers and deferred work

- **External completion enforcement:** Hoster's installed `@narumitw/pi-goal` `goal_complete` lives in its external tool implementation and calls `transitionGoal(..., "complete")` without consulting BBH run state. This BBH change records and instructs the parent; it cannot technically block a bypassing caller. A separate approved source/fork integration must bind a goal ID to a run state and validate before transition, preserving non-BBH goals and positive completions. Do not edit the installed npm copy or claim a hard gate or production activation from this branch alone.
- **Inventory completeness:** Coverage brief only contains registered questions; source artifact references come from the parent, not automatic cross-corpus ingestion. Missing ledger remains a mapping gap; no auto-discovery or percentage is promised.
- **Agent-evaluation decision quality:** two paired local parent scenarios and one less-guided paired scenario yielded sound continuation in both arms, with no demonstrated uplift. Natural installed-runtime skill/CLI discovery and a real goal completion interception remain untested; do not claim behavioral effectiveness or activation from these fixtures.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/goal-coverage-checkpoint-t4c8370c7`
- **Latest immutable recovery checkpoint:** `42e5a4c3b136240ff579c02f5c2b0f73cc4a0891` (class-identity implementation; check later handoff-only tip separately)
- **Feature implementation commit(s):** `af8e8670992de298de66cff50765d69df7d7d48b`, `8256a1e4f2ef43c3b5d2d2a31cdc83fcb2dddc08`, `42e5a4c3b136240ff579c02f5c2b0f73cc4a0891`
- **Exact resume point:** obtain fresh independent review of the class-identity repair, then decide beta integration separately from runtime activation.
- **Working-tree state at handoff:** implementation committed; this dossier update is a later handoff-only commit.

## Decision gates

- **Integration gate:** independent review of exact implementation and tests; updated beta reconciliation and integrated tests.
- **Activation / cohort gate:** runtime source and loaded goal skills verified; local simulation is not real goal-run proof.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-18 — isolated feature branched from fetched beta; implemented TDD goal-only checkpoint and source-scoped guidance.
- 2026-10-18 — first independent review blocked three issues; repaired them test-first. Matched local agents made sound decisions in both arms, so no uplift claim. Pi completion hook is a separate source/integration boundary.
- 2026-10-18 — second review blocked broad-goal class identity; repaired test-first. Less-guided local pair again made sound decisions in both arms without demonstrated uplift.
