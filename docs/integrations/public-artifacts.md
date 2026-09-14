# Public Artifacts Consumer Integration Dossier

## Intent

Expose the reviewed Bounty Core public-artifact registry to BBH through a small
CLI and the `public-artifacts` skill. The operational contract is private-first,
own-community preference, one-artifact reuse, and verified terminal cleanup.

## Scope and boundary

- **Consumer branch:** `bug-bounty-harness/t_e018bd51-add-public-artifacts-skill-and-bounty-co`
- **Base / target:** `origin/beta` at `44062cd` → `beta`
- **Provider pin:** Bounty Core beta `8f0a11ca54e99e183d75d3099572716eaf027734`.
- **Changed paths:** `agents/public_artifacts.py`, its integration test, `skills/public-artifacts/SKILL.md`, and the Bounty Core pin/runtime dependency test.
- **Non-goals:** changing `public-forums` policy, choosing a public destination, publishing an artifact, or activating/synchronizing the new skill.

## Evidence

- Installed the pinned provider using `bash setup.sh --install-python-deps`.
- `uv pip freeze --python .venv/bin/python` confirms the exact provider SHA.
- `.venv/bin/python -m pytest -q agents/test_public_artifacts.py tests/test_runtime_dependencies.py` — 4 passed.
- The full `agents tests` suite ran: 1,400 passed plus 94 subtests, with 8 pre-existing unrelated failures in AppMap/report navigation and stale AGENTS/skill-command expectations. None mention a changed path.
- `git diff --check` passed before the consumer dossier.

## Review and integration gate

Obtain a fresh no-edit review that reconciles the provider SHA, installed provenance, CLI lifecycle behavior, skill policy, and changed-path test receipts. After approval, merge into current BBH beta, re-run the installed focused checks, push only from the beta worktree, and read back the remote SHA. Skill synchronization/runtime activation remains separate.
