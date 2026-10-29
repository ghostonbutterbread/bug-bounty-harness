# Baseline documentation failures integration dossier

- **Status:** review-ready; independent review approved
- **Owner:** Hermes bugfix, Kanban `t_65665071`
- **Branch:** `fix/papercut-baseline-doc-tests`
- **Base commit:** `33ba01fa32613804697272ac5a502aecb7abee0b` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-28
- **Owning feature branch/ref:** `fix/papercut-baseline-doc-tests`
- **Latest immutable recovery checkpoint:** `28d1865f7a1dfd75cc523afe1299f63f1b48fade`
- **Feature implementation commit(s):** `4c1c4851c27ce3bb124b0f577527f97720d35b25`
- **Inspiration / canonical references:** `PC-20261027-015844-064d4082`; BBH `AGENTS.md`, `SCRIPT_POLICY.md`.

## Intent

Repair three confirmed baseline documentation-test failures without changing upload safety behavior or running live target tests. Align the stack-to-program script map with the repository's index and lane-safety contracts; fix an obsolete upload-surface test to assert the existing owned-public versus direct-impact approval distinction.

## Implemented contract

The index uses the required `Outputs`/`Mutates` labels, retains its documented `bbh` example and offline unit verification, and no longer directs agents to a checkout-selected executable. Upload-surface test preserves existing gates and checks both ordinary owned public rendering and direct-impact approval/lease routing. The upload skill itself is unchanged.

## Evidence and review

- Before edit: focused pytest against feature worktree returned 3 failures, 1 passed, 7 subtests passed; failures were missing index fields, direct-checkout command, and obsolete baseline-upload wording.
- After edit: `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_script_policy.py tests/test_skill_command_lane_safety.py tests/test_upload_surface_skill.py tests/test_stack_to_program.py` returned 35 passed, 13 subtests passed. Tests compute ROOT from this feature checkout. `git diff --check` passed.
- Independent review: approved reviewed tip `28d1865f7a1dfd75cc523afe1299f63f1b48fade`, no blocking findings; independently reproduced baseline failures and reran 35 tests plus 13 subtests and four offline unittest cases. Confirmed feature-resolved test roots and preserved upload approval boundary.
- Merge/ancestry evidence: based on fetched beta `33ba01fa`; refetch and reconcile before review/integration.

## Blockers and deferred work

Integrated-tree tests are pending; these block papercut closure. No managed runtime activation is included. Stable promotion requires explicit authorization.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-baseline-doc-tests`
- **Latest immutable recovery checkpoint:** `28d1865f7a1dfd75cc523afe1299f63f1b48fade`; use feature tip after this decision update.
- **Feature implementation commit(s):** `4c1c4851c27ce3bb124b0f577527f97720d35b25`; use feature tip after commit.
- **Exact resume point:** fetch and reconcile current beta, merge the reviewed branch, remove this temporary dossier from the integration tree, and run focused tests.
- **Working-tree state at handoff:** intended clean after initial commit.

## Decision gates

- **Integration gate:** independent review, clean reconciliation and focused tests.
- **Activation / cohort gate:** none requested; publication is not runtime activation.
- **Promotion gate:** explicit stable authorization.

## Decision record

- 2026-10-28 — reproduced current beta failures and implemented narrow documentation/test correction.
- 2026-10-28 — independent reviewer approved the implementation; merge and integrated-tree verification remain.
