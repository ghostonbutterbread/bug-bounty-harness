# Program-scoped inventory reference audit

## Intent
Update BBH guidance that still printed an unnormalized program inventory path, after the account-inventory path fix was integrated into `beta`.

## Scope and boundary
- Branch: `docs/program-scoped-inventory-references`
- Base / target: `beta` at `6497e5bd2076fd9c4ce96bf6263c6d28bdb0a945`
- User context: Discord bug-fixes thread message `1543007565406019585`
- Only documentation references; runtime code was audited separately.

## Implemented contract
Updated every remaining direct BBH guidance reference to use `$HARNESS_SHARED_BASE/{normalized-program}/credentials/account_inventory.json`, including Chromium, IDOR, and access-control guidance. The text now explicitly rejects browser-lane and generic inventory paths.

## Evidence
- A bounded source audit found exactly four runtime consumers: account manager, auth resolver, Chromium launcher, and browser-profile lease. All import the canonical `inventory_paths` helper.
- No direct unnormalized `$HARNESS_SHARED_BASE/{program}/credentials/account_inventory.json` reference remains in `prompts`, `skills`, `agents`, or `scripts`.
- `auto-recon` and `autonomous-recon` contain no `account_inventory` consumers.
- Installed account-management scripts resolve to this BBH checkout.
- `uv run --with pytest pytest -q agents/test_account_inventory.py agents/test_auth_resolver.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py` → `70 passed in 3.29s`.
- `git diff --check` passed.

## Next action
Commit this documentation-completeness audit and merge it into `beta`.
