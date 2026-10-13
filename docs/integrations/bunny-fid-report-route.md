# Bunny FID report route integration dossier

- **Status:** feature
- **Owner:** Hermes / Ryushe
- **Branch:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Base commit:** `9632b607ffe445257ca3544e0330cd9705b70275` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-12
- **Owning feature branch/ref:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryu's correction in the current thread; BBH `security-reporting`, `manual-hunter`, `agents/index.md`; standalone `ghostonbutterbread/bunny-report-and-triage` fork; Bounty Core finding packet and navigation contracts.

## Intent

After a demonstrated finding, retain the ledger FID and populated `reports/<FID>/EVIDENCE.md`; invoke the standalone Bunny reporting skill for one `reports/<FID>/<domain>-<vuln>-<FID>.md` plus a PoC where required. No new rough `REPORT.md` or `SUBMISSION.md`. Preserve historical packets and operator-only submission state. Integrate into beta after cross-repo provider acceptance and installed provenance checks; no stable promotion or Hoster activation implied.

## Implemented contract

In progress: BBH routing and skill-owner guidance point to the external skill, not a copied fork implementation. Bounty Core must provide evidence-only packet creation and navigation without accidentally generating `REPORT.md`. BBH must use this mode on finding ingestion, edits, submission status, sync/promotion and refresh, and register the exact FID-named report after review without overwriting it. The report/PoC and independent readiness checks belong to the agent skill; code does not automatically run an agent or a live exploit.

## Evidence and review

- Tests and commands: policy test in progress; code and integration tests pending provider API.
- Independent review: pending.
- Replay/cohort/fixture evidence: synthetic packet ingest, refresh, report-registration, and legacy preservation pending.
- Merge/ancestry evidence: feature worktree fast-forwarded to fetched `origin/beta` at `9632b60`.

## Blockers and deferred work

- **Missing test or evidence:** Bounty Core provider mode, immutable pin, installed provenance, full BBH producer and navigation tests, independent review.
- **Command / fixture / environment needed:** isolated Bounty Core feature tests, BBH checkout-local installer and `agents/test_manual_hunter.py` plus reporting/ledger suites with a task-owned synthetic root.
- **Trigger to run it:** provider acceptance and published immutable beta SHA.
- **Why it blocks integration, activation, or promotion:** current Bounty Core writes `REPORT.md` on ledger updates and navigation refresh.
- **Next completion step / successor reference:** integrate provider, pin, implement BBH routing, test and review, then beta merge and separate runtime activation decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** finish policy tests; await provider API, implement BBH adapter and final report registration.
- **Working-tree state at handoff:** intentionally uncommitted implementation in progress.

## Decision gates

- **Integration gate:** provider published/read back, BBH pinned and installed, focused and regression tests, fresh independent review, clean beta merge.
- **Activation / cohort gate:** verify selected runtime's BBH checkout/dependency and installed standalone Bunny skill, then synthetic no-target write smoke; no live target needed.
- **Promotion gate:** stable branch requires separate explicit approval.

## Decision record

- 2026-10-12 — Ryu chose FID-named Bunny report and removed new `REPORT.md`/`SUBMISSION.md`; existing artifacts preserved. Beta-first implementation begun.
