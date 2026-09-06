# BBH `me` → `ledger` migration

- **Task:** `t_647e6c55`
- **Branch:** `feat/split-me-ledger`
- **Base / target:** `origin/beta` at `0d6f47e` → `beta`
- **Scope:** rename the BBH coordination skill to `ledger`; preserve ledger,
  coverage, report-pipeline, and durable hunt-note guidance; update direct
  BBH documentation references.
- **Activation boundary:** merge this removal/rename to BBH `beta` before adding
  the same-named general `me` projection, then perform focused sync verification
  so no duplicate `me` skill remains.

## Evidence

- `bbh agents/test_manual_hunter.py` (18 tests)
- `python3 -m unittest tests.test_skill_command_lane_safety tests.test_migrated_skill_commands tests.test_portable_shell_launchers`
- Repository-wide search finds no remaining BBH `skills/me`, `/me` command, or
  stale manual-hunter handoff references.

## Review / next action

Independent review is required before commit and beta integration. On approval,
commit this branch, merge it into a clean current `beta`, and keep this dossier
out of the integration branch via the immediate integration cleanup.
