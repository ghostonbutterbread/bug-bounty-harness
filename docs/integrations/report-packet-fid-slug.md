# Finding packet layout integration dossier

- **Status:** feature
- **Owner:** Hermes / t_f9946642
- **Branch:** `feat/report-packet-fid-slug-tf9946642`
- **Base commit:** `0e6fbc95d7f22c51f04eced826d31f21f7ac259b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`
- **Feature implementation commit(s):** `16fdd0e2932a7fde127a1234742e088f0d34979f`, `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`
- **Inspiration / canonical references:** `/home/ryushe/.hermes/plans/2026-10-13_152453-report-packet-layout.md`; Bounty Core provider branch `feat/report-packet-fid-slug-tf9946642`.

## Intent

Consume Bounty Core's stable FID-and-vulnerability-slug packet path, retain exact FID final-report registration, and route BBH skills to the resolved evidence packet. Prove all behaviors without contacting a target or mutating production Shared data.

## Implemented contract

BBH consumes the provider's persisted `finding['report_dir']` for new descriptive evidence packets and retains exact-FID legacy packet reads. Registration remains a pre-existing FID-named report handoff; operator submission changes generate/remove navigation without moving evidence. Sync skips canonical D-number packet artifacts, but still imports raw reports. Dynamic validation's packet lookup and lifecycle scan follow the ledger pointer. Standalone Bunny and profile-local finding-ingestion skills contain the requested one-line-paragraph instruction and ledger-resolved packet guidance; BBH's security-reporting, root card, and bounty-notes examples align.

Provider feature implementation: `a879453c0ea084e944455d9453592cf7048b1103`, dossier tip `23d0c6183db4119413c9b5c93e8f6c2b09d146de`. **This is a local contract smoke only, not installed provenance or an integrated release.**

## Evidence and review

- Baseline: `python3 -m pytest agents/test_finding_report.py agents/test_manual_hunter.py -q` — 38 passed, 13 subtests passed on fetched origin/beta.
- Consumer RED: descriptive path + submission E2E tests in `agents/test_finding_report.py` and `agents/test_manual_hunter.py` failed on old FID-only provider; provider source-contract smoke now passes their focused suites.
- Consumer local contract smoke: `PYTHONPATH=<provider-feature-worktree>:<BBH-feature-worktree> python3 -m pytest agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_dynamic_validation.py agents/test_report_checker.py agents/test_base_team_review.py -q --tb=short` — **2 failed, 128 passed, 13 subtests passed**, after BBH reader/test reconciliation. Two failures exercise a legacy-format ledger carrying `report_dir`: provider `migrate_legacy_finding` drops it through `_merge_extra_fields` (reserved), so descriptive packet lookup fails. The base-team path regression was corrected and reran green; rerun full focused command after provider fix. These source-path tests are preliminary; no pinned installed package was used.
- Sync/dynamic baseline on old provider after packet exclusion: `python3 -m pytest agents/test_sync_reports.py agents/test_dynamic_validation.py -q` — 63 passed.
- Independent Bounty Core provider review: dispatched, pending.
- Fixture E2E: pending.
- Merge/ancestry evidence: feature based on fetched `origin/beta` 0e6fbc95d7f22c51f04eced826d31f21f7ac259b.

## Blockers and deferred work

- **Missing test or evidence:** Provider review, preservation of `report_dir` during legacy-ledger migration (2 BBH regressions), then installed Bounty Core provider release and BBH pin provenance plus new packet end-to-end CLI cycle.
- **Command / fixture / environment needed:** provider `pytest tests/`, BBH focused command above against immutable installed pin, disposable root CLI create/register/submit/reverse plus full BBH tests.
- **Trigger to run it:** provider review and targeted fix, provider beta published and pinned.
- **Why it blocks integration, activation, or promotion:** source-only provider edits do not reach BBH's installed dependency, and a legacy-normalized pointer is currently lost.
- **Next completion step / successor reference:** review/fix provider, publish beta, pin/install BBH, rerun tests, independent BBH review, beta integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`
- **Feature implementation commit(s):** `16fdd0e2932a7fde127a1234742e088f0d34979f`, `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`
- **Exact resume point:** accept independent provider review, fix legacy ledger `report_dir` preservation, then publish provider beta, pin/reinstall BBH, and run full installed E2E.
- **Working-tree state at handoff:** task-owned BBH reconciliations committed as checkpoint; verify status before further edits.

## Decision gates

- **Integration gate:** provider published/pinned, consumer tests and independent review pass, current beta reconciled.
- **Activation / cohort gate:** verify installed dependency and synchronized Bunny/BBH skill content in selected runtime.
- **Promotion gate:** none requested; stable is separate.

## Decision record

- 2026-10-13 — created BBH feature worktree and recorded baseline; provider implementation delegated in separate repository.
