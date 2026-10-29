# Parameter mining playbook path integration dossier

- **Status:** feature; independent review pending
- **Owner:** Hermes bugfix, Kanban `t_5a10c0a6`.
- **Branch / owning ref:** `fix/parameter-mining-playbook-path`.
- **Worktree:** `/home/ryushe/worktrees/bbh-parameter-mining-playbook-path`.
- **Base:** `3fa84b824c9cbefbba2dcb0d09e3bb11b331c335` (fetched `origin/beta`).
- **Target:** `beta`; stable promotion and runtime activation not authorized.
- **Last updated:** 2026-10-28.
- **Recovery checkpoint / implementation:** `df092f0f2137db6d400b22f22eccc3dbe38f3686`.
- **Inspiration:** `PC-20261011-parameter-mining-playbook-path`.

## Intent and implemented contract

Projected parameter-mining skill names a repo-relative playbook but does not identify its root. Route the lookup through `bbh --print-command`, which returns the actual selected checkout's path, and instruct agents to detect projected-skill/launcher checkout mismatch before using it. No duplicated playbook, absolute machine path, target access or new runtime behavior.

## Evidence and review

- Current bugfix runtime: `bbh --root` and projected skill resolved to the same beta checkout; skill-relative `prompts/...` was absent and root-relative playbook existed.
- RED: `tests/test_parameter_mining_playbook_route.py::test_parameter_mining_playbook_uses_checkout_resolver` failed before the skill change on the missing command.
- GREEN: `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q tests/test_parameter_mining_playbook_route.py tests/test_skill_command_lane_safety.py tests/test_script_policy.py` returned 29 passed; test uses distinct synthetic stable/beta checkout sentinels and fails closed when selected playbook is missing.
- First independent review blocked `af231b5`: launcher documentation described only executables and mismatch instructions were not actionable. Updated launcher docs to distinguish dispatch from non-executing file resolution, and the skill to compare `bbh --root` with physical skill source and stop on mismatch or unknown provenance. Added an explicit projected-skill mismatch fixture. Focused red assertion failed before these changes; the full 29-test selection now passes.
- `git diff --check` passed. Independent re-review pending; fetch beta and reconcile before integration.

## Blockers and deferred work

Independent re-review and integrated-tree checks are pending. Runtime projection/activation must be verified separately before closing the papercut. If selected skill and launcher lanes differ, resolve the mismatch rather than silently reading the wrong playbook. No deployment, target interaction or stable promotion is authorized by this branch.

## Interruption / resume handoff

- **Owning branch:** `fix/parameter-mining-playbook-path`.
- **Checkpoint:** `df092f0f2137db6d400b22f22eccc3dbe38f3686`; review feature tip including this handoff update.
- **Exact resume point:** independent review of focused diff and lane/negative tests; reconcile current beta; run integrated checks; verify active projection.
- **Working tree:** intended clean after initial commit.

## Decision gates

- **Integration:** independent review, current beta ancestry and passing checks.
- **Activation:** separately verify selected runtime and loaded skill; do not claim activation from publication alone.
- **Promotion:** explicit owner direction required.

## Decision record

- 2026-10-28 — reproduced ambiguous path and wrote lane-bound resolver guidance with regression tests.
- 2026-10-28 — resolved two independent-review blockers; re-review pending.
