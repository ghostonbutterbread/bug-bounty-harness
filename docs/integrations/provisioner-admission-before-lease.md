# Browser provisioner admission before lease

## Intent

Prevent a capacity-rejected browser request from changing the health state of an otherwise usable persistent profile.

## Base and target

- Feature branch: `fix/provisioner-admission-before-lease`
- Base: `beta` at `3177735c`
- Intended integration target: `beta`

## Contract

- Capacity admission runs before profile acquisition.
- A `queued` / `no-capacity` result does not acquire, release, alter health, or start a profile browser.
- Existing post-acquisition launch-failure cleanup remains unchanged, because only that path may have affected profile state.

## Verification

`uv run --with pytest pytest -q agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_chromium_test_launcher.py` passed: 61 tests.

## Review

An independent review approved the implementation: the rejection regression observes both lease calls (including cleanup releases) and `subprocess.run`, so it would fail under the old acquire-then-cancel ordering. No defect was found.

## Activation boundary

This is source-only until the reviewed change is merged into `beta` and the Hoster runtime is explicitly fast-forwarded to the resulting commit. Hoster currently has complete swap exhaustion and nine Chromium roots in unmanaged sibling `app-org.chromium.*` scopes; no live browser restart or profile cleanup is part of this change.

## Resume point

- Implementation checkpoint: `bdfd2b152aacd4efcde895521179e2fe6e7de74f`.
- Review the focused two-file implementation diff and its regression, then merge it into a clean, current `beta` worktree. Remove this dossier from `beta` during the integration operation.
