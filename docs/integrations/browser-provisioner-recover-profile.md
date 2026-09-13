# Browser provisioner recovery forwarding integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/browser-provisioner-recover-profile`
- **Base commit:** `5e48d4e844246f3010d6cfd2bc2e476289eb1663`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-13
- **Owning feature branch/ref:** `fix/browser-provisioner-recover-profile`
- **Latest immutable recovery checkpoint:** pending first commit
- **Inspiration / canonical references:** preserved dirty Hoster provisioner change; `browser_profile_lease.py` recovery-lease contract

## Intent

Expose the existing lease manager's `--recover-profile` capability through both
browser provisioner entry points so an approved repair/re-authentication run can
lease an otherwise unavailable but eligible profile.

## Implemented contract

`start` forwards `--recover-profile` to the lease-acquire command, and `request`
forwards it to its repeated `start` invocation. Both CLI subcommands document
that the flag is only for repair/re-authentication and requires a healthy release
before ordinary reuse. No default lease behavior changes.

## Evidence and review

- Preserved Hoster diff was compared against the current beta source and the
  existing lease-manager implementation, which already accepts and gates
  `--recover-profile`.
- Focused tests: `python3 -m pytest agents/test_browser_provisioner.py agents/test_browser_profile_lease.py -q` — 33 passed.
- CLI validation: both `start --help` and `request --help` contain
  `--recover-profile`.
- `git diff --check` passed.
- Live browser/profile actions: none.

## Blockers and deferred work

- **Missing test or evidence:** independent review and clean beta integration validation.
- **Command / fixture / environment needed:** reviewer diff inspection; beta merge check.
- **Trigger to run it:** before merge.
- **Why it blocks integration:** profile-recovery access must preserve lease ownership and healthy-release constraints.
- **Next completion step / successor reference:** obtain independent review, then merge only if the safety and compatibility checks pass.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-provisioner-recover-profile`
- **Latest immutable recovery checkpoint:** pending first commit.
- **Exact resume point:** stage the two implementation files and this dossier, commit, then request independent review.
- **Working-tree state at handoff:** implementation is uncommitted.

## Decision gates

- **Integration gate:** focused tests, CLI checks, independent review, and a clean beta merge check.
- **Activation gate:** refresh Hoster's clean beta checkout and run the normal profile-scoped/full synchronizer workflow.
- **Promotion gate:** no main promotion implied.
