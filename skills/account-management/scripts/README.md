# Account Management Scripts

## `account_inventory.py`

- **Purpose:** Create and maintain the non-secret, program-scoped inventory of
  owned accounts, resources, login links, and integrations.
- **Inputs:** Program slug and the selected inventory subcommand.
- **Outputs:** Structured receipts and the canonical account inventory.
- **Mutates:** The selected program's account inventory for write subcommands;
  read commands do not mutate it.
- **Example:** `bbh skills/account-management/scripts/account_inventory.py show <program>`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_account_inventory.py -q`
- **Owner/scope:** Account Management skill.
- **Last verified:** 2026-09-10.

## `auth_resolver.py`

- **Purpose:** Resolve approved owned-account authentication handoffs without
  exposing secret values.
- **Inputs:** Program, account, operation, and registered inventory/auth references.
- **Outputs:** Sanitized resolution, status, or refresh receipts.
- **Mutates:** Explicit refresh operations write the approved auth seed (with
  `captured_at`) and its inventory reference. When `resolve` actually runs the
  declared liveness check, it records the non-secret result in the account's
  `auth_seed_status`; it never rewrites the seed itself. See
  [`../references/auth-seed-health.md`](../references/auth-seed-health.md).
- **Example:** `bbh skills/account-management/scripts/auth_resolver.py resolve --program <program> --account <alias>`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest skills/account-management/scripts/test_auth_resolver.py agents/test_auth_resolver.py agents/test_auth_seed_health.py agents/test_account_inventory.py -q`
- **Owner/scope:** Account Management skill; planning-time seed usability lives in `agents/auth_seed_health.py`.
- **Last verified:** 2026-11-24.

## `inventory_paths.py`

- **Purpose:** Provide dependency-free canonical path and program-key helpers to
  the account scripts. Existing Chromium Test launchers also import it; this is
  a retained compatibility dependency, not the placement pattern for new
  cross-skill modules.
- **Inputs:** Program name and optional `HARNESS_SHARED_BASE` configuration.
- **Outputs:** Normalized program keys and inventory paths.
- **Mutates:** Nothing.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_account_inventory.py -q`
- **Owner/scope:** Account Management skill, with legacy Chromium Test consumers.
- **Last verified:** 2026-09-10.

All three helpers implement bounded account-management mechanics. Their output
does not independently establish account ownership, session validity, or
complete authorization coverage.
