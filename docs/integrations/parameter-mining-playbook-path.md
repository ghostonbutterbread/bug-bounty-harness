# Parameter mining playbook path integration dossier

- **Status:** feature; independent review approved before beta reconciliation, re-review pending
- **Owner:** Hermes bugfix, Kanban `t_5a10c0a6`.
- **Branch / owning ref:** `fix/parameter-mining-playbook-path`.
- **Worktree:** `/home/ryushe/worktrees/bbh-parameter-mining-playbook-path`.
- **Base:** `3fa84b824c9cbefbba2dcb0d09e3bb11b331c335` (fetched `origin/beta`).
- **Target:** `beta`; stable promotion and runtime activation not authorized.
- **Last updated:** 2026-10-28.
- **Recovery checkpoint:** `4b5dfc48ad8bae0fac579f7c2739d49c0bd07f48`; implementation `df092f0f2137db6d400b22f22eccc3dbe38f3686`, review corrections `a0a6b29ff22d96069e4e9f5b80e24ea9e22daf7e`.
- **Inspiration:** `PC-20261011-parameter-mining-playbook-path`.

## Intent and implemented contract

Projected parameter-mining skill names a repo-relative playbook but does not identify its root. Route the lookup through `bbh --print-command`, which returns the actual selected checkout's path, and instruct agents to detect projected-skill/launcher checkout mismatch before using it. No duplicated playbook, absolute machine path, target access or new runtime behavior.

## Evidence and review

- Current bugfix runtime: `bbh --root` and projected skill resolved to the same beta checkout; skill-relative `prompts/...` was absent and root-relative playbook existed.
- RED: `tests/test_parameter_mining_playbook_route.py::test_parameter_mining_playbook_uses_checkout_resolver` failed before the skill change on the missing command.
- GREEN: `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_parameter_mining_playbook_route.py tests/test_skill_command_lane_safety.py tests/test_script_policy.py` returned 29 passed; test uses distinct synthetic stable/beta checkout sentinels and fails closed when selected playbook is missing.
- First independent review blocked `af231b5`: launcher documentation described only executables and mismatch instructions were not actionable. Updated launcher docs to distinguish dispatch from non-executing file resolution, and the skill to compare `bbh --root` with physical skill source and stop on mismatch or unknown provenance. Added an explicit projected-skill mismatch fixture. Focused red assertion failed before these changes; the full 29-test selection now passes.
- Independent re-review approved `a0a6b29ff22d96069e4e9f5b80e24ea9e22daf7e`, with 43 tests passed and no blockers. The mismatch check is agent guidance, not a mechanically enforced agent stop. Its fixture proves source-root inequality.
- Beta advanced to `6f34e62bcda278cba7d29d50916271f0b0c30171`; merged into feature `0c1e3a1c48b241d12981a2bb4a1132e9e6420141` and reran 43 tests successfully. `git diff --check` passed; independent reconciliation re-review pending.
- Independent reviewer approved reconciled `1d665d36c61c0924b70b9b8c352b86f322d1471f` and passed 43 tests. Beta subsequently advanced to `379e8fcc1dfc89b967a4cc2b260a09b5c842efbb`; merged into `04eba39c4c6d6483250a5c4a8e758a44ca757a9b` without conflicts and reran 43 tests. Final reconciliation review remains.
- Independent reviewer approved `77a6a63c7ccce060d3aaf09b72f1f5cbe0f94655`, rerunning 43 tests. Beta then advanced to `f8b3253fb4abebc4e1016728b6d82106be74deb3`; merged into `4b5dfc48ad8bae0fac579f7c2739d49c0bd07f48` without conflicts and reran 43 tests. Fresh reconciliation review remains.

## Blockers and deferred work

Independent re-review and integrated-tree checks are pending. Runtime projection/activation must be verified separately before closing the papercut. If selected skill and launcher lanes differ, resolve the mismatch rather than silently reading the wrong playbook. No deployment, target interaction or stable promotion is authorized by this branch.

## Interruption / resume handoff

- **Owning branch:** `fix/parameter-mining-playbook-path`.
- **Checkpoint:** `4b5dfc48ad8bae0fac579f7c2739d49c0bd07f48`; review feature tip including this handoff update.
- **Exact resume point:** independent review of focused diff and lane/negative tests; reconcile current beta; run integrated checks; verify active projection.
- **Working tree:** intended clean after initial commit.

## Decision gates

- **Integration:** independent review, current beta ancestry and passing checks.
- **Activation:** separately verify selected runtime and loaded skill; do not claim activation from publication alone.
- **Promotion:** explicit owner direction required.

## Decision record

- 2026-10-28 — reproduced ambiguous path and wrote lane-bound resolver guidance with regression tests.
- 2026-10-28 — resolved two independent-review blockers; re-review pending.
- 2026-10-28 — re-review approved, merged advanced beta and passed 43 tests; independent reconciliation review pending.
- 2026-10-28 — reconciliation review approved, merged further advanced beta and reran 43 tests; final review pending.
- 2026-10-28 — latest reconciliation review approved; merged advanced beta and reran 43 tests; fresh reconciliation review pending.
