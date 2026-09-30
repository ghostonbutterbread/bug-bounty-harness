# Security-reporting PoC owner integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch / owning ref:** `docs/security-reporting-poc-owner`
- **Base commit:** `34339045941d894fdb6f402551d2133fb99462ed`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Canonical reference:** `skills/security-reporting/SKILL.md`

## Intent

Remove ambiguity between the report writer and PoC author without changing the specialist PoC creation or live-testing authority. Preserve prior evidence and avoid repeated material mutations solely for writing polish.

## Implemented contract

Primary hunter owns PoC proof and final artifact, may delegate artifact construction with bounded context, and checks the result. Reporter owns the submission and report/PoC alignment, returns gaps to the hunter, and does not independently trigger live exploitation. A new live test needs a named unresolved proof question and applicable controls.

## Evidence and review

- Focused test: `python -m unittest tests.test_security_reporting_skill` — 3 tests passed; `git diff --check` clean.
- Policy neighbors checked: `poc-tooling-policy`, `triager-first-poc-authoring`, `hunt-orchestration-policy`, `bunny-reporter.md`, `agents/index.md`. These retain specialist artifact and live authorization ownership; no competing author assignment found.
- Independent review: pending.
- Merge/ancestry: branch created from fetched `origin/beta` at base SHA above.

## Blockers and deferred work

- None identified for source-level integration. Runtime activation requires the selected beta source projection and a fresh consumer check; do not claim it from a commit alone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/security-reporting-poc-owner`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** run focused checks and independent review, then reconcile current beta, integrate, and verify projection.
- **Working-tree state at handoff:** pending commit.

## Decision gates

- **Integration:** focused test, policy consistency and independent review pass; remove this dossier from beta integration.
- **Activation:** verify active skill projection and fresh consumer read.
- **Promotion:** no stable promotion without separate direction.

## Decision record

- Created on feature branch to assign proof-of-concept ownership at the canonical reporting boundary.
