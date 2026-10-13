# Bunny FID report route integration dossier

- **Status:** feature
- **Owner:** Hermes / Ryushe
- **Branch:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Base commit:** `9632b607ffe445257ca3544e0330cd9705b70275` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Latest immutable recovery checkpoint:** `22c0f4047f68358f20b7d61f285340d31f058ef8`
- **Feature implementation commit(s):** `66d8176` (policy), `741319b` (BBH evidence-only implementation), `22c0f40` (beta revert reconciliation)
- **Inspiration / canonical references:** Ryu's correction in the current thread; BBH `security-reporting`, `manual-hunter`, `agents/index.md`; standalone `ghostonbutterbread/bunny-report-and-triage` fork; Bounty Core finding packet and navigation contracts.

## Intent

After a demonstrated finding, retain the ledger FID and populated `reports/<FID>/EVIDENCE.md`; invoke the standalone Bunny reporting skill for one `reports/<FID>/<domain>-<vuln>-<FID>.md` plus a PoC where required. No new rough `REPORT.md` or `SUBMISSION.md`. Preserve historical packets and operator-only submission state. Integrate into beta after cross-repo provider acceptance and installed provenance checks; no stable promotion or Hoster activation implied.

## Implemented contract

Implementation: BBH adapter uses Bounty Core `packet_mode=evidence_only` for updates and navigation. New FIDs receive only create-once `EVIDENCE.md`; manual ingestion and CLI hand off the FID and packet. The old `finding_submission.py` refuses to create a competing artifact. After the standalone Bunny skill writes a reviewed FID-named report, `agents/finding_report.py` registers its existing file (never writes report text or claims submission). Dynamic validation resolves registered FID reports or evidence, while legacy paths remain readable. No AI agent or live exploit is automatically launched by the code.

## Evidence and review

- Tests and commands: provider `beta` `9968eeb58ca902549097d8941875b0e01cfe0af2` published/read back after 165 passing provider tests and independent ACCEPT. BBH checkout-local `./setup.sh --install-python-deps` installed that exact SHA; `direct_url.json` shows the pinned commit and the `.venv` module path. Installed BBH combined route/compatibility/dynamic-validation tests: 363 passed, 51 subtests. Synthetic registration CLI round-trip and submitted-state receipt regression passed. Root-level `pytest` cannot collect unrelated `test_catalog.py` without its `bac_checks` module.
- Independent review: provider initial REVISE security findings repaired in `7810622b`; fresh independent rereview ACCEPT with adversarial probes and 165 passing tests. BBH final reviewer returned REVISE on `edeaba2`: provider-confirmed findings with `status=active` vanished from lifecycle ingestion; registration CLI falsely emitted `submitted=false` for an already-submitted finding. Both corrected with focused installed-environment regressions; fresh BBH rereview required before merge.
- Replay/cohort/fixture evidence: synthetic packet ingest, report registration, and legacy artifact preservation covered using installed pinned provider; no live target used.
- Merge/ancestry evidence: BBH feature base `9632b60`; merged fetched `origin/beta` revert `9f31d8b` into feature without retaining its removed surface-coverage workflow. Provider remote beta read back at `9968eeb58ca902549097d8941875b0e01cfe0af2`.

## Blockers and deferred work

- **Missing test or evidence:** final BBH independent review and standalone Bunny fork acceptance. Its current feature skill still names `REPORT.md`/`SUBMISSION.md` as input and is not published/installed; EVIDENCE.md input support, fork review/publication, and a synthetic report-only output smoke are required before activating this reporting route.
- **Command / fixture / environment needed:** review BBH diff/dossier and installed `.venv/bin/python -m pytest ...`; from an isolated populated `reports/<FID>/EVIDENCE.md`, load the published standalone Bunny skill, author one report-only output and confirm no other packet files changed.
- **Trigger to run it:** BBH review now; fork-specific smoke after the revised fork main is published and installed in the selected skill runtime.
- **Why it blocks integration, activation, or promotion:** BBH beta needs independent consumer acceptance; a BBH beta merge alone cannot prove the external skill accepts EVIDENCE.md or is installed. Treat publication and runtime activation separately.
- **Next completion step / successor reference:** BBH review and any narrow fixes, beta merge/test/push/read-back, then separate runtime skill activation.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_66f0802d-replace-canonical-bbh-final-report-route`
- **Latest immutable recovery checkpoint:** `22c0f4047f68358f20b7d61f285340d31f058ef8`
- **Feature implementation commit(s):** `66d8176` (policy), `741319b` (BBH evidence-only implementation), `22c0f40` (beta revert reconciliation)
- **Exact resume point:** await BBH consumer review; then merge into BBH beta, test installed dependency and read back remote; runtime skill availability is a separate activation gate.
- **Working-tree state at handoff:** clean after provider-pin implementation checkpoint.

## Decision gates

- **Integration gate:** provider published/read back, BBH pinned and installed, focused and regression tests, fresh independent review, clean beta merge.
- **Activation / cohort gate:** verify selected runtime's BBH checkout/dependency and installed standalone Bunny skill, then synthetic no-target write smoke; no live target needed.
- **Promotion gate:** stable branch requires separate explicit approval.

## Decision record

- 2026-10-12 — Ryu chose FID-named Bunny report and removed new `REPORT.md`/`SUBMISSION.md`; existing artifacts preserved. Beta-first implementation begun.
