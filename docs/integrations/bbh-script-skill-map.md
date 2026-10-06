# BBH skill-first script discovery integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/bbh-script-skill-map`
- **Base commit:** `bdce1f39cb277b43ccd7ee8e95fa2df35f1ae975`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `docs/bbh-script-skill-map`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `SCRIPT_POLICY.md`, `agents/index.md`, `skills/xss/SKILL.md` Scripts map, `scripts/README.md`.

## Intent

Give BBH agents a skill-first route from the appropriate subskill to its indexed scripts and, conditionally, to the next owning skill. Include the otherwise unowned cross-skill root helpers and Bounty Tools' intentionally empty category catalog. No script logic, live target traffic, or policy/scope changes.

## Implemented contract

Bottom `## Scripts map` pointers in the seven remaining indexed script-owner skills and `bb-script-rules`; the root script index routes its eight helpers to relevant owners. Bounty Tools points to its own empty category catalog, root tool runner and Recon Bus, and conditional specialist skills. Preserve the XSS precedent and the existing canonical script records. A focused regression verifies owner pointers, local map links, and root helper route coverage. Fix one misleading BountyLens helper path.

## Evidence and review

- Tests and commands: `python3 -m pytest tests/test_script_policy.py -q` (26 passed after final refinement); `git diff --check` passed. Broader `tests/test_hoster_script_authority.py` and `tests/test_skill_command_lane_safety.py` fail on unchanged beta files; reproduced both against the clean beta checkout, matching existing papercut PC-20261006-025055.
- Independent review: pending.
- Replay/cohort/fixture evidence: static documentation and path audit only; no target traffic.
- Merge/ancestry evidence: feature starts at fetched `origin/beta` `bdce1f3`.
- Policy alignment: `SCRIPT_POLICY.md` owns placement and index, `agents/index.md` routes `/bb-script-rules` with the relevant skill, XSS provides existing map precedent, Bounty Tools owns tool execution (not specialist proof); no duplicate operational rule introduced.

## Blockers and deferred work

- No change-specific blockers. Pre-existing baseline failures above prevent a clean broader suite receipt. Fresh-agent/runtime activation is distinct from the Git change and must be verified after integration; do not claim remote-host deployment.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/bbh-script-skill-map`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** rerun focused verification, review exact diff, checkpoint/commit, independent review, then integrate into `beta` if accepted.
- **Working-tree state at handoff:** intentionally uncommitted pending tests and review.

## Decision gates

- **Integration gate:** all local script-policy tests pass, links resolve, independent review accepts, fetched beta remains compatible.
- **Activation / cohort gate:** read back active beta source and resolved skill links; fresh read-only discovery if activation is requested.
- **Promotion gate:** no stable/main promotion requested.

## Decision record

- 2026-10-06 — created a bounded BBH skill/index navigation branch; no runtime changes.
