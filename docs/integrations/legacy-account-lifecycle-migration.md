# Legacy account lifecycle migration

- **Task:** Let agents canonically migrate recognized legacy account lifecycle values instead of relying indefinitely on compatibility reads.
- **Branch / base / target:** `fix/migrate-legacy-account-lifecycle` / `338abd4ad58e75b635db4beb0190fd7da603eacd` (`beta`) / `beta`.
- **Implemented contract:** `account_inventory.py migrate-lifecycle <program>` atomically rewrites only `live` to `active`; `--dry-run` reports affected aliases without writing; repeat runs report `no-changes`. Unknown lifecycle strings remain unchanged.
- **Evidence:** `uv run --with pytest python -m pytest agents/test_account_inventory.py agents/test_browser_profile_lease.py agents/test_browser_provisioner.py agents/test_chromium_test_launcher.py -q` — 69 passed. Python compilation and `git diff --check` passed.
- **Activation boundary:** The command is source-only until beta integration, Hoster Aiskillsync, and an explicit targeted run for a program inventory.
- **Review / merge decision:** Self-review confirmed the command uses the existing atomic inventory writer, changes only the explicit `live → active` mapping, preserves unknown values, and has dry-run/idempotency regression coverage. Accepted for local beta integration.
- **Next:** Merge to beta, sync Hoster, then run `migrate-lifecycle superdrug` to update the selected shared inventory.
