# Program-scoped account inventories

## Intent
Ensure every BBH account-management, auth-resolution, Chromium launcher, and browser-profile-lease path resolves the same inventory for one normalized program key. No generic or lane-specific alternate inventory may be created or read.

## Scope and boundary
- Branch: `fix/program-scoped-account-inventories`
- Base: `beta` at `813fc6a1610646d52a8e5b2f774bbc7f69d21cd2`
- Intended target: `beta`
- Source: Discord bug-fixes thread message `1542999635025600612`
- Non-secret metadata only; do not migrate or modify live account registries.

## Implemented contract
- Added `skills/account-management/scripts/inventory_paths.py` as the canonical program-key and inventory-path helper.
- Account inventory, auth resolver, Chromium launcher, and browser-profile lease now resolve exactly `$HARNESS_SHARED_BASE/<normalized-program>/credentials/account_inventory.json`.
- Chromium no longer adds a `web/` subdirectory when `HARNESS_SHARED_BASE` is unset, so it cannot silently read a second account inventory for the same program.
- Program labels normalize consistently (for example, `Acme Platform` → `acme-platform`).

## Evidence and verification
- `uv run --with pytest pytest -q agents/test_account_inventory.py agents/test_auth_resolver.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py` → `70 passed in 5.30s`.
- `python3 -m py_compile` passed for all changed Python modules.
- `git diff --check` passed.
- The new regression proves all four consumers resolve `Acme Platform` to one inventory path and that Chromium does not select a `web/credentials` alternate.

## Blockers / activation
Kanban task setup is unavailable in this execution context; recorded as shared papercut `PC-20260828-205304-46d41af5`. This does not block repository-local implementation.

## Next action
Review the focused diff, commit the feature branch, and merge it into a clean current `beta` worktree.
