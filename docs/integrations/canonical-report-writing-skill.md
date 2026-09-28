# Canonical BBH report-writing skill integration dossier

- **Status:** feature
- **Owner:** Hermes Agent
- **Branch:** `feat/canonical-report-writing-skill`
- **Base commit:** `74db0772e459b646297a98d5dacd112d466879ed`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-28
- **Owning feature branch/ref:** `feat/canonical-report-writing-skill`
- **Latest immutable recovery checkpoint:** `cfd161d` (initial receiver and routes)
- **Feature implementation commit(s):** `cfd161d` (evidence-contract follow-up pending)
- **Inspiration / canonical references:** General Skills beta `skills/security-reporting` and `skills/evidence-first-vulnerability-reporting`; active bugfix-profile reporting references reviewed for unique evidence and judge contracts.

## Intent

Make BBH the sole canonical owner of security report-writing guidance. Fold the two overlapping General Skills skills into one BBH capability without changing Bounty Core's generated finding packet, submitting externally, or inventing evidence. Paired General Skills cleanup branch: `chore/move-reporting-skills-to-bbh`, base `7b2f85e`, target `beta`.

## Implemented contract

BBH `skills/security-reporting/SKILL.md` owns evidence-first package, five-section concise submission, complementary guided PoC and request/response manual replay, no references to our other reports, and independent judge. `manual-hunter` and Bunny reporter route to it. `REPORT.md` remains a ledger-derived packet, not an automatic final submission; `FINALIZED.md` and confirmed findings are not platform submission events. General Skills removes both duplicate skills after receiving BBH source is verified.

## Evidence and review

- Tests and commands: `test_security_reporting_skill.py` (2), `test_bunny_skill.py` (4), and `agents/test_manual_hunter.py` (24) passed; `git diff --check` passed. Full repo suite not run because this is skill/routing-only.
- Independent review: CHANGES — preserve explicit Evidence Report structure, reconcile profile-local duplicate skill copies, and correct committed dossier checkpoints. Evidence structure restored here; profile cleanup is an activation gate.
- Replay/cohort/fixture evidence: no live target traffic; documentation/skill-only migration.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** clean paired source integration and profile runtime link reconciliation.
- **Command / fixture / environment needed:** BBH + General Skills beta merges, profile-scoped Aiskillsync dry-run/apply/no-op, fresh consumer resolution on local and Hoster.
- **Trigger to run it:** after independent review passes and both source branches are committed.
- **Why it blocks integration, activation, or promotion:** split ownership or a duplicate skill name would make runtime resolution ambiguous.
- **Next completion step / successor reference:** reconcile review, integrate BBH first, then General Skills deletion, sync and verify.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/canonical-report-writing-skill`
- **Latest immutable recovery checkpoint:** `cfd161d` (initial receiver and routes)
- **Feature implementation commit(s):** `cfd161d` (evidence-contract follow-up pending)
- **Exact resume point:** verify evidence-contract follow-up and final reviewed diff, then integrate BBH before General Skills cleanup and sync.
- **Working-tree state at handoff:** clean after follow-up commit; confirm at handoff.

## Decision gates

- **Integration gate:** independent review and focused tests, then reconcile beta tips.
- **Activation / cohort gate:** source pair integrated and runtime projection resolves BBH skill only; fresh-agent read.
- **Promotion gate:** beta only; no main promotion requested.

## Decision record

- 2026-09-28 — BBH selected as single canonical report-writing owner; General Skills duplicate definitions scheduled for deletion after BBH adoption.
