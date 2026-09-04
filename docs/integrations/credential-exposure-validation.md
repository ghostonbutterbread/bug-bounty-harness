# Credential-exposure validation skill integration dossier

## Intent
Add a BBH skill that separates validation of target-disclosed login credentials and a capped default-admin configuration check from wordlists, spraying, stuffing, and brute force.

## Source and target
- Base: `beta` at `496fa9f8e7c34aa607881151ec4d824034dd5cd3`
- Feature branch: `bug-bounty-harness/t_25f4b6b0-add-credential-exposure-validation-skill`
- Worktree: `/home/ryushe/projects/bug_bounty_harness/.worktrees/t_25f4b6b0`
- Intended integration target: `beta`

## Implemented contract
- New `skills/credential-exposure-validation/SKILL.md` routes exposed username/password pairs to bounded in-scope panel validation and permits a capped three-pair default-admin check.
- The skill states that program-specific auth, password/default-credential, spraying, and named-panel restrictions control; a generic no-brute-force rule does not prohibit validating a complete pair already exposed by the target.
- A successful authentication records only minimal proof and stops before post-login exploration.
- `/js` explicitly hands complete, in-scope exposed username/password pairs to the new skill rather than a wordlist lane.
- `SKILL_REGISTRY.md` exposes the skill command.

## Evidence
- `python3 -m unittest tests.test_credential_exposure_validation_skill tests.test_migrated_skill_commands tests.test_skill_command_lane_safety` — passed (6 tests).
- `git diff --check` and `git diff --cached --check` — passed after staging every task-owned file.
- `python3 -m unittest discover -s tests` — blocked before affected tests by missing local `bounty_core` imports in nine pre-existing recon/program test modules; focused skill, dispatcher, and lane-safety tests pass.
- Independent review identified and the branch fixed resource-safety routing, the JavaScript Lens, JS/registry integration test coverage, and whole-feature diff-check coverage; narrow re-review approved the staged result with no findings.

## Activation boundary
This branch prepares the BBH source skill. It is not active in a synced runtime until the reviewed change is integrated into `beta` and the relevant BBH skill projection is synchronized and verified in a fresh runtime.

## Next action
Obtain independent review, address concrete findings, re-run the focused checks, then make a local feature-branch commit.
