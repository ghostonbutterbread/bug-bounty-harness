# Security-reporting PoC owner integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch / owning ref:** `docs/security-reporting-poc-owner`
- **Base commit:** `34339045941d894fdb6f402551d2133fb99462ed`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `b7ad2f9880101731dba2b0238fe19f7b902a1b4f`
- **Feature implementation commit(s):** `b7ad2f9880101731dba2b0238fe19f7b902a1b4f`
- **Canonical reference:** `skills/security-reporting/SKILL.md`

## Intent

Remove ambiguity between the report writer and PoC author without changing the specialist PoC creation or live-testing authority. Preserve prior evidence and avoid repeated material mutations solely for writing polish.

## Implemented contract

Primary hunter owns PoC proof and final artifact, may delegate artifact construction with bounded context, and checks the result. Reporter owns the submission and report/PoC alignment, returns gaps to the hunter, and does not independently trigger live exploitation. A new live test needs a named unresolved proof question and applicable controls.

## Evidence and review

- Focused test: `python -m unittest tests.test_security_reporting_skill` — 3 tests passed; `git diff --check` clean.
- Policy neighbors checked: `poc-tooling-policy`, `triager-first-poc-authoring`, `hunt-orchestration-policy`, `bunny-reporter.md`, `agents/index.md`. These retain specialist artifact and live authorization ownership; no competing author assignment found.
- Independent review: PASS, no blocking findings; reviewer reran `git diff --check` and all 3 focused tests. Non-blocking note: wording-marker test cannot detect every possible future contradiction.
- Merge/ancestry: branch created from fetched `origin/beta` at base SHA above.

## Blockers and deferred work

- None identified for source-level integration. Runtime activation requires the selected beta source projection and a fresh consumer check; do not claim it from a commit alone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/security-reporting-poc-owner`
- **Latest immutable recovery checkpoint:** `b7ad2f9880101731dba2b0238fe19f7b902a1b4f`
- **Feature implementation commit(s):** `b7ad2f9880101731dba2b0238fe19f7b902a1b4f`
- **Exact resume point:** reconcile current beta, integrate, and verify projection.
- **Working-tree state at handoff:** clean after this handoff-only commit.

## Decision gates

- **Integration:** focused test, policy consistency and independent review pass; remove this dossier from beta integration.
- **Activation:** verify active skill projection and fresh consumer read.
- **Promotion:** no stable promotion without separate direction.

## Decision record

- Created on feature branch to assign proof-of-concept ownership at the canonical reporting boundary.
- Independent review passed; accepted for beta integration with no deferred source-level checks. Do not promote to stable implicitly.
