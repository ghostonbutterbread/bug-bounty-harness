# Parent/subagent PoC ownership integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch / owning ref:** `docs/security-reporting-poc-parent-child`
- **Base commit:** `4a0260a6b7b5c0ec8d34bd274a72c0ad38270f24`
- **Intended integration target:** `beta`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Canonical reference:** `skills/security-reporting/SKILL.md`

## Intent

Avoid treating “primary hunter” as necessarily the main agent when a subagent holds the first-hand proof. Keep one PoC owner per finding and coordinator accountability; preserve the report-writer and live-testing boundaries.

## Implemented contract

Coordinating agent names a finding/PoC owner per FID. Main hunter or hunting subagent may author if it established proof; a mapping-only child returns observations. Coordinator checks the proof, finalizes one artifact and sends a sanitized handoff to the report writer. PoC author loads specialist skills; delegation does not expand live authorization.

## Evidence and review

- Focused test: `python -m unittest tests.test_security_reporting_skill` — 3 passed; `git diff --check` clean.
- Neighbor checks: `poc-tooling-policy`, `triager-first-poc-authoring`, `coordination`, `hunt-orchestration-policy`, `agents/index.md`; no competing report-writer authorship rule.
- Independent review: pending.

## Blockers and deferred work

- None identified; runtime activation is distinct from source integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/security-reporting-poc-parent-child`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** test and review, then reconcile with beta and integrate.
- **Working-tree state at handoff:** pending commit.

## Decision gates

- **Integration:** focused tests and independent review pass; remove dossier from beta.
- **Activation:** read active symlink and current skill content.
- **Promotion:** stable untouched absent explicit direction.

## Decision record

- Created to clarify that the finding-context holder can be parent or child while one coordinator remains accountable.
