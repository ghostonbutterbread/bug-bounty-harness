# Parent/subagent PoC ownership integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch / owning ref:** `docs/security-reporting-poc-parent-child`
- **Base commit:** `4a0260a6b7b5c0ec8d34bd274a72c0ad38270f24`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** `07d232ffe2c115719715a6cebe0666a396d980ff`
- **Feature implementation commit(s):** `07d232ffe2c115719715a6cebe0666a396d980ff`
- **Canonical reference:** `skills/security-reporting/SKILL.md`

## Intent

Avoid treating “primary hunter” as necessarily the main agent when a subagent holds the first-hand proof. Keep one PoC owner per finding and coordinator accountability; preserve the report-writer and live-testing boundaries.

## Implemented contract

Coordinating agent names a finding/PoC owner per FID. Main hunter or hunting subagent may author if it established proof; a mapping-only child returns observations. Coordinator checks the proof, finalizes one artifact and sends a sanitized handoff to the report writer. PoC author loads specialist skills; delegation does not expand live authorization.

## Evidence and review

- Focused test: `python -m unittest tests.test_security_reporting_skill` — 3 passed; `git diff --check` clean.
- Neighbor checks: `poc-tooling-policy`, `triager-first-poc-authoring`, `coordination`, `hunt-orchestration-policy`, `agents/index.md`; no competing report-writer authorship rule.
- Independent review: PoC ownership wording passed, no policy conflicts. Reviewer reran 3 focused tests and `git diff --check origin/beta...HEAD`; flagged this dossier's stale checkpoint/handoff fields, corrected here.

## Blockers and deferred work

- None identified; runtime activation is distinct from source integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/security-reporting-poc-parent-child`
- **Latest immutable recovery checkpoint:** `07d232ffe2c115719715a6cebe0666a396d980ff`
- **Feature implementation commit(s):** `07d232ffe2c115719715a6cebe0666a396d980ff`
- **Exact resume point:** reconcile with current beta, integrate and verify projection.
- **Working-tree state at handoff:** clean after this handoff-only commit.

## Decision gates

- **Integration:** focused tests and independent review pass; remove dossier from beta.
- **Activation:** read active symlink and current skill content.
- **Promotion:** stable untouched absent explicit direction.

## Decision record

- Created to clarify that the finding-context holder can be parent or child while one coordinator remains accountable.
- Independent review accepted the policy change after stale handoff metadata was corrected; ready for beta integration. No stable promotion implied.
