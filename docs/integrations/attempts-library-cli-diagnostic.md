# Attempts library CLI diagnostic integration dossier

- **Status:** feature; independent release review pending.
- **Owner:** Hermes bugfix, Kanban `t_a0058941`.
- **Branch/worktree:** `fix/attempts-library-cli-diagnostic`, `/home/ryushe/worktrees/bbh-attempts-library-cli-diagnostic`.
- **Base:** `6f34e62bcda278cba7d29d50916271f0b0c30171` (`origin/beta`).
- **Target:** `beta`; no stable promotion or runtime activation implied.
- **Last updated:** 2026-10-28.
- **Recovery checkpoint / implementation:** `6a51208a843725f66bcd60576a0e8a59c57abc0e`.
- **Inspiration:** `PC-20261022-233604-9046d9c8`.

## Intent and implemented contract

`agents.attempts` is a library; treating it as a CLI previously succeeded without writing anything. When run as a module or file, fail nonzero with an actionable explanation and point to the existing canonical `docs/attempt-recording-contract.md` through the BBH path diagnostic. Imports, persistence, storage, redaction and library APIs are unchanged. This does not add a CLI or make any target request.

## Evidence and review

- RED: `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q agents/test_attempts.py::test_attempts_module_cli_fails_with_actionable_library_guidance` failed because direct module invocation exited 0 with no output.
- GREEN: `HOME="$TMPDIR" PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q agents/test_attempts.py` returned 8 passed. The test exercises module and file invocation in an isolated home; a direct file invocation independently returned diagnostic and exit 1. No target data written.
- `git diff --check` passed. Fresh independent release review and post-integration verification pending.

## Blockers and deferred work

Review, beta reconciliation and integrated tests are required before integration. The historically affected runtime must be checked separately before closure. No existing attempt records are modified.

## Interruption / resume handoff

- **Branch:** `fix/attempts-library-cli-diagnostic`.
- **Recovery checkpoint:** `6a51208a843725f66bcd60576a0e8a59c57abc0e`.
- **Exact resume:** fresh review and focused tests; fetch beta; integrate and verify selected runtime before closing papercut.
- **Working tree:** intended clean after commit.

## Decision gates

- **Integration:** independent review, current beta ancestry, integrated tests.
- **Activation:** separate approval/verification.
- **Stable:** explicit owner direction.

## Decision record

- 2026-10-28 — reproduced silent success and added library-only diagnostic.
