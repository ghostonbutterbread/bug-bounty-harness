# Bunny FID report route integration dossier

- **Status:** feature
- **Owner:** Hermes / Ryushe
- **Branch:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Base commit:** `9632b607ffe445257ca3544e0330cd9705b70275` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-12
- **Owning feature branch/ref:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Latest immutable recovery checkpoint:** `741319b`
- **Feature implementation commit(s):** `66d8176` (policy), `741319b` (BBH evidence-only implementation)
- **Inspiration / canonical references:** Ryu's correction in the current thread; BBH `security-reporting`, `manual-hunter`, `agents/index.md`; standalone `ghostonbutterbread/bunny-report-and-triage` fork; Bounty Core finding packet and navigation contracts.

## Intent

After a demonstrated finding, retain the ledger FID and populated `reports/<FID>/EVIDENCE.md`; invoke the standalone Bunny reporting skill for one `reports/<FID>/<domain>-<vuln>-<FID>.md` plus a PoC where required. No new rough `REPORT.md` or `SUBMISSION.md`. Preserve historical packets and operator-only submission state. Integrate into beta after cross-repo provider acceptance and installed provenance checks; no stable promotion or Hoster activation implied.

## Implemented contract

Implementation: BBH adapter uses Bounty Core `packet_mode=evidence_only` for updates and navigation. New FIDs receive only create-once `EVIDENCE.md`; manual ingestion and CLI hand off the FID and packet. The old `finding_submission.py` refuses to create a competing artifact. After the standalone Bunny skill writes a reviewed FID-named report, `agents/finding_report.py` registers its existing file (never writes report text or claims submission). Dynamic validation resolves registered FID reports or evidence, while legacy paths remain readable. No AI agent or live exploit is automatically launched by the code.

## Evidence and review

- Tests and commands: BBH synthetic tests against local Bounty Core feature checkout `0a966b7`: 147 passed, 51 subtests across ingestion, edit, sync, base-team, CLI, dynamic validation, and policy. `pytest -q agents tests` reaches unrelated suites but has two historical assertion failures now updated; root-level `pytest` cannot collect `test_catalog.py` without an unrelated `bac_checks` module.
- Independent review: provider review returned REVISE on `0a966b7`: a symlinked FID packet can escape reports root before failure, and an untrusted report_path may point to another FID, including a legacy deletion path. Bounty Core fix in progress on provider feature branch; BBH reviewer pending. Do not pin/merge the uncorrected provider.
- Replay/cohort/fixture evidence: synthetic packet ingest, report registration, and legacy artifact preservation covered; installed immutable provenance pending.
- Merge/ancestry evidence: feature worktree fast-forwarded to fetched `origin/beta` at `9632b60`.

## Blockers and deferred work

- **Missing test or evidence:** security repair and independent re-review of Bounty Core provider; publish an accepted immutable SHA, pin BBH, install from that pin, complete broader regression and BBH review.
- **Command / fixture / environment needed:** local provider test suite, BBH checkout-local installer and synthetic fixture tests using the installed distribution (not PYTHONPATH).
- **Trigger to run it:** independent provider acceptance and published immutable beta SHA.
- **Why it blocks integration, activation, or promotion:** a local PYTHONPATH proof does not validate an installed dependency or reachable pin.
- **Next completion step / successor reference:** accept and publish provider, pin and install BBH, test and review, then beta merge and separate runtime activation decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Latest immutable recovery checkpoint:** `741319b`
- **Feature implementation commit(s):** `66d8176` (policy), `741319b` (BBH evidence-only implementation)
- **Exact resume point:** await provider security repair/re-review and BBH review; then publish provider beta, pin and install BBH, verify, integrate.
- **Working-tree state at handoff:** clean after review-blocker dossier checkpoint.

## Decision gates

- **Integration gate:** provider published/read back, BBH pinned and installed, focused and regression tests, fresh independent review, clean beta merge.
- **Activation / cohort gate:** verify selected runtime's BBH checkout/dependency and installed standalone Bunny skill, then synthetic no-target write smoke; no live target needed.
- **Promotion gate:** stable branch requires separate explicit approval.

## Decision record

- 2026-10-12 — Ryu chose FID-named Bunny report and removed new `REPORT.md`/`SUBMISSION.md`; existing artifacts preserved. Beta-first implementation begun.
