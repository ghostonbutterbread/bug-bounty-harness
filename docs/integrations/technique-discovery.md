# Technique Discovery integration dossier

- **Status:** blocked (review accepted; beta integration pending)
- **Owner:** Hermes Agent, Kanban `t_3991a8e7`
- **Branch:** `feat/technique-discovery`
- **Base commit:** `f4196f7b0798cbddad390b585466fa4843ab0ad2` (`origin/beta` fetched 2026-10-07)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `feat/technique-discovery`
- **Latest immutable recovery checkpoint:** `507a57bf37e45c742d1a93cc7adee5fb0a353077`
- **Feature implementation commit(s):** `944184efa00c1e2647a612e28c228327ccfb7fbd`, `507a57bf37e45c742d1a93cc7adee5fb0a353077`
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
- GREEN: `PYTHONPATH=. python3 -m unittest tests/test_technique_discovery_skill.py -v` — 6 passed initially; after reviewer fixes, adjacent `tests/test_technique_discovery_skill.py tests/test_goal_router.py tests/test_patch_analysis_skill.py -q` — 12 passed.
- Full isolated suite: `PYTHONPATH=. python3 -m unittest discover -s tests -q` — after reviewer fixes, 137 run, 1 skipped, 1 failed. The sole failure is `test_skill_command_lane_safety` detecting obsolete direct-Python examples inside an unrelated tracked `docs/integrations/broad-goal-map-reconciliation.md`; `git show f4196f7:<path>` proves the offending line is in the fetched base commit. No feature path appears in the failure.
- `git diff --check` passed.
- Independent review: BLOCK on initial tip `97ba217` (class-only registry and missing `safe-fetch` route); after fixes, independent read-only re-review **ACCEPT** for committed range `f4196f7..5c522de` (prior blockers resolved, no feature regression identified). Reviewer notes the tests are textual contract checks, not a real discovery-run evaluation.
- Merge/ancestry: feature based on fetched `origin/beta`; local beta root is behind and contains unrelated tracked modification `skills/waf/SKILL.md`.

## Blockers and deferred work

- **Missing test or evidence:** a clean full suite on the integration baseline, clean beta integration, and post-merge suite.
- **Command / fixture / environment needed:** resolve the unrelated tracked legacy dossier/test scan in its owning change, then use a clean beta integration worktree, fresh fetch and focused/full tests with checkout-first `PYTHONPATH`.
- **Trigger to run it:** the unrelated baseline test failure is repaired in its own change, and the dirty root-beta WAF edit is safely resolved by its owner.
- **Why it blocks integration, activation, or promotion:** the current full suite is red on baseline and root beta holds an unrelated tracked modification; do not merge around/overwrite it. Live skill projection requires a separate activation decision.
- **Next completion step / successor reference:** address the pre-existing suite failure as an independently owned fix and reconcile beta cleanliness; fetch current beta, rerun focused/full checks, then integrate reviewed feature and verify projection only after an explicit activation decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/technique-discovery`
- **Latest immutable recovery checkpoint:** `507a57bf37e45c742d1a93cc7adee5fb0a353077`
- **Feature implementation commit(s):** `944184efa00c1e2647a612e28c228327ccfb7fbd`, `507a57bf37e45c742d1a93cc7adee5fb0a353077`
- **Exact resume point:** review has accepted the corrected implementation `507a57bf37e45c742d1a93cc7adee5fb0a353077`; resolve the two named integration blockers, then preflight current beta without touching unrelated work. Do not claim a green full suite or merge while they remain.
- **Working-tree state at handoff:** clean after committing the reviewer fixes and final handoff.

## Decision gates

- **Integration gate:** passing tests, independent review, clean current beta.
- **Activation / cohort gate:** separate skill sync decision; source merge is not a runtime activation.
- **Promotion gate:** no stable/main promotion without Ryushe direction.

## Decision record

- 2026-10-07 — created isolated feature from fetched `origin/beta`; focused test RED then skill/registry implementation.
- 2026-10-07 — committed implementation as `944184efa00c1e2647a612e28c228327ccfb7fbd`; full suite baseline failure and root-beta dirt remain integration blockers.
- 2026-10-07 — review blocked on invocation syntax and untrusted source retrieval; amended skill, registry and tests, plus Program Docs routing. Focused 12 green; full 137 has only inherited failure.
- 2026-10-07 — reviewer fixes committed at `507a57bf37e45c742d1a93cc7adee5fb0a353077`; awaiting independent re-review.
- 2026-10-07 — fresh independent re-review accepted range through `5c522ded70fce314454d112fe481c3c2156c8730`; integration withheld because baseline suite and root beta are not clean.
