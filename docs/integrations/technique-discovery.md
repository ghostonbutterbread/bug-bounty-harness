# Technique Discovery integration dossier

- **Status:** feature
- **Owner:** Hermes Agent, Kanban `t_3991a8e7`
- **Branch:** `feat/technique-discovery`
- **Base commit:** `f4196f7b0798cbddad390b585466fa4843ab0ad2` (`origin/beta` fetched 2026-10-07)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `feat/technique-discovery`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe's Technique Discovery discussion and reviewed seed `/home/ryushe/Shared/skill_seeds/2026-10-05-technique-discovery.md`; current BBH `skills/bug-goals/SKILL.md`, `SKILL_REGISTRY.md`.

## Intent

Create an explicitly invoked, standalone research workflow for application-led and stack-led security technique discovery. It should derive falsifiable mechanisms from a concrete stack or program observation, avoid duplicate ordinary hunting, and route results into existing stores. It must not make ordinary `/goal` runs auto-invoke the skill or grant live testing authority.

## Implemented contract

- New `skills/technique-discovery/SKILL.md`: trigger language, entry modes, evidence-driven research loop, local negative controls, novelty classification, target applicability, stop condition and output packet.
- Registry row for direct `/technique-discovery {class}` invocation with optional program/stack.
- Focused contract tests in `tests/test_technique_discovery_skill.py`.
- No goal-router or live runtime changes; no claim a novel exploit has been found.

## Evidence and review

- RED: focused tests failed because skill file did not exist (expected).
- GREEN: `PYTHONPATH=. python3 -m unittest tests/test_technique_discovery_skill.py -v` — 6 passed; adjacent `tests/test_technique_discovery_skill.py tests/test_goal_router.py tests/test_patch_analysis_skill.py -q` — 10 passed.
- Full isolated suite: `PYTHONPATH=. python3 -m unittest discover -s tests -q` — 135 run, 1 skipped, 1 failed. The sole failure is `test_skill_command_lane_safety` detecting obsolete direct-Python examples inside an unrelated tracked `docs/integrations/broad-goal-map-reconciliation.md`; `git show HEAD:<path>` proves the offending line is in the fetched base commit. No feature path appears in the failure.
- `git diff --check` passed.
- Independent review: pending.
- Merge/ancestry: feature based on fetched `origin/beta`; local beta root is behind and contains unrelated tracked modification `skills/waf/SKILL.md`.

## Blockers and deferred work

- **Missing test or evidence:** a clean full suite on the integration baseline, clean beta integration, and post-merge suite.
- **Command / fixture / environment needed:** resolve the unrelated tracked legacy dossier/test scan in its owning change, then use a clean beta integration worktree, fresh fetch and focused/full tests with checkout-first `PYTHONPATH`.
- **Trigger to run it:** independent review passes and unrelated dirty root-beta work is safely resolved by its owner.
- **Why it blocks integration, activation, or promotion:** the current full suite is red on baseline and root beta holds an unrelated tracked modification; do not merge around/overwrite it. Live skill projection requires a separate activation decision.
- **Next completion step / successor reference:** commit focused feature and obtain independent review; address the pre-existing suite failure as an independently owned fix and reconcile beta cleanliness before merge.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/technique-discovery`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** review diff, commit feature, seek independent review. Do not claim a green full suite or merge while the baseline test and root-beta dirt remain.
- **Working-tree state at handoff:** intentionally uncommitted while implementing.

## Decision gates

- **Integration gate:** passing tests, independent review, clean current beta.
- **Activation / cohort gate:** separate skill sync decision; source merge is not a runtime activation.
- **Promotion gate:** no stable/main promotion without Ryushe direction.

## Decision record

- 2026-10-07 — created isolated feature from fetched `origin/beta`; focused test RED then skill/registry implementation.
