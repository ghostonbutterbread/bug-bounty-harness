# Attempts library CLI diagnostic integration dossier

- **Status:** reconciled feature approved by independent re-review; integration pending.
- **Owner:** Hermes bugfix, Kanban `t_a0058941`.
- **Branch/worktree:** `fix/attempts-library-cli-diagnostic`, `/home/ryushe/worktrees/bbh-attempts-library-cli-diagnostic`.
- **Base:** `6f34e62bcda278cba7d29d50916271f0b0c30171` (`origin/beta`).
- **Target:** `beta`; no stable promotion or runtime activation implied.
- **Last updated:** 2026-10-28.
- **Recovery checkpoint:** `aa6111ac7a0cf3324747dd2fc850a7f4f5000f2e`; implementation `6a51208a843725f66bcd60576a0e8a59c57abc0e`.
- **Inspiration:** `PC-20261022-233604-9046d9c8`.

## Intent and implemented contract

`agents.attempts` is a library; treating it as a CLI previously succeeded without writing anything. When run as a module or file, fail nonzero with an actionable explanation and point to the existing canonical `docs/attempt-recording-contract.md` through the BBH path diagnostic. Imports, persistence, storage, redaction and library APIs are unchanged. This does not add a CLI or make any target request.

## Evidence and review

- RED: `PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q agents/test_attempts.py::test_attempts_module_cli_fails_with_actionable_library_guidance` failed because direct module invocation exited 0 with no output.
- GREEN: `HOME="$TMPDIR" PYTHONDONTWRITEBYTECODE=1 /home/ryushe/worktrees/bbh-beta-integration-offline/.venv/bin/python -m pytest -p no:cacheprovider -q agents/test_attempts.py` returned 8 passed. The test exercises module and file invocation in an isolated home; a direct file invocation independently returned diagnostic and exit 1. No target data written.
- Independent review approved `af0071fa8488f9de9544c06150174b0d2b46d3d9`: 8 attempts tests plus 8 related checks passed; module/file invocation and no-write behavior verified. Beta then advanced to `379e8fcc1dfc89b967a4cc2b260a09b5c842efbb`; merged it into checkpoint `64831481279f86c253445f885b999d47c2c2a59f` and reran 8 attempts tests. `git diff --check` passed. Re-review and integrated verification pending.
- Independent reconciliation review approved `aa6111ac7a0cf3324747dd2fc850a7f4f5000f2e`, confirmed the reviewed implementation was unchanged and reran 8 attempts tests with synthetic HOME. Integrated verification remains.

## Blockers and deferred work

Review, beta reconciliation and integrated tests are required before integration. The historically affected runtime must be checked separately before closure. No existing attempt records are modified.

## Interruption / resume handoff

- **Branch:** `fix/attempts-library-cli-diagnostic`.
- **Recovery checkpoint:** `aa6111ac7a0cf3324747dd2fc850a7f4f5000f2e`.
- **Exact resume:** fetch beta, integrate reviewed feature and run tests; verify affected runtime before closing papercut.
- **Working tree:** intended clean after commit.

## Decision gates

- **Integration:** independent review, current beta ancestry, integrated tests.
- **Activation:** separate approval/verification.
- **Stable:** explicit owner direction.

## Decision record

- 2026-10-28 — reproduced silent success and added library-only diagnostic.
- 2026-10-28 — independent review approved, merged advanced beta and reran tests; reconciliation re-review pending.
- 2026-10-28 — reconciliation re-review approved; integration pending.
