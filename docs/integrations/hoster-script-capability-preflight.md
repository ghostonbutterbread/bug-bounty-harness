# Hoster Script Capability Preflight

## Intent

Replace BBH's blanket Hoster source prohibition with a capability-based rule that
cannot drift from the configured GitHub credential.

## Ownership

- Task: `t_c9e43fa7`
- Branch: `fix/hoster-script-capability-preflight`
- Base: `5ef9b5b304fa3ce995e3700d32f3e7d4789539ee`
- Target: `beta`
- Changed boundary: repository guidance and its deterministic regression only

## Contract

An explicitly authorized existing-script repair may use the normal shared coding
operations workflow only after a non-mutating write check proves the current
credential can write this repository. Missing access routes to a proposal packet.
Skill or policy changes route to a skill seed. No machine or repository allowlist
is duplicated in BBH guidance.

## Evidence

- Red regression: `tests/test_hoster_script_authority.py` failed against the
  blanket execution-only sentence.
- Green regression: `1 passed in 0.01s`.
- Existing Script Manager/launcher-focused suites: `56 passed in 4.90s`.
- Complete `tests/` suite: `110 passed, 2 failed, 84 subtests passed`.
  Both failures are pre-existing on unchanged beta: the broad-goal dossier lane
  failure was already recorded in `BUGFIXES.md`; the Bounty Core revision
  expectation now has its own backlog entry.
- Independent review: approved with no blockers. Two low test/handoff findings
  were corrected before integration.
- Bounded re-review: no remaining findings; repository binding and named-
  allowlist rejection were mutation-tested.

## Activation boundary

Repository guidance only. No credential, repository setting, runtime, stable
branch, or unrelated script is changed.

## Next action

Rerun the corrected regression and focused suite, obtain bounded re-review, then
follow the normal beta integration gate.
