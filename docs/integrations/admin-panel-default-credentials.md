# Admin-panel default credential campaign dossier

## Intent
Update `credential-exposure-validation` so every mapped in-scope privileged login panel triggers automatic bounded default-admin coverage: five likely pairs when the program does not expressly prohibit brute force/spraying on that panel, or one to five documentation-informed pairs when it does.

## Source and target
- Base: `beta` at `1c20fd3550e5da0c6237ae15062be8102ac6c3f4`
- Feature branch: `feat/admin-panel-default-credentials`
- Worktree: `/home/ryushe/worktrees/bbh-admin-panel-default-credentials`
- Intended integration target: `beta`

## Implemented contract
- The skill triggers when mapping reaches an in-scope admin, claim, portal, or privileged login panel.
- Any authentication-testing or default-password-guessing prohibition blocks all default-credential submissions. Otherwise, absent a panel-specific brute-force/spraying prohibition, it tries at most five fixed likely default/admin pairs—each backed by product/version/panel documentation or observed in-scope target configuration—at the program’s stated login rate, or normal rate-safe baseline with backoff when no rate is published.
- A specific brute-force/spraying prohibition blocks that five-pair campaign but permits one to five evidence-supported default pairs—at that same stated rate or baseline/backoff—unless the earlier no-submission gate applies.
- It remains bounded: no generic wordlist, account-list variation, lockout retries, or post-login exploration.

## Evidence
- `python3 -m unittest tests.test_credential_exposure_validation_skill tests.test_migrated_skill_commands tests.test_skill_command_lane_safety` — passed (6 tests).
- `git diff --check` — passed.

## Activation boundary
This is a source-only change until independently reviewed, merged into `beta`, and synchronized into the applicable runtime.

## Next action
Run focused tests, obtain independent review, address concrete findings, then commit the feature branch.
