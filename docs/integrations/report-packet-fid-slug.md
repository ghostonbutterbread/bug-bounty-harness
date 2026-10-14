# Finding packet layout integration dossier

- **Status:** feature
- **Owner:** Hermes / t_f9946642
- **Branch:** `feat/report-packet-fid-slug-tf9946642`
- **Base commit:** `0e6fbc95d7f22c51f04eced826d31f21f7ac259b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** `420ef2dd2aafa485d15bebefec0b4d5ee547e614`
- **Feature implementation commit(s):** `16fdd0e2932a7fde127a1234742e088f0d34979f`, `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`, `252a2e6131cf84a134d98ce0304c4b660b6f9bbb`, `420ef2dd2aafa485d15bebefec0b4d5ee547e614`
- **Inspiration / canonical references:** `/home/ryushe/.hermes/plans/2026-10-13_152453-report-packet-layout.md`; Bounty Core provider branch `feat/report-packet-fid-slug-tf9946642`.

## Intent

Consume Bounty Core's stable FID-and-vulnerability-slug packet path, retain exact FID final-report registration, and route BBH skills to the resolved evidence packet. Prove all behaviors without contacting a target or mutating production Shared data.

## Implemented contract

BBH consumes the provider's persisted `finding['report_dir']` for new descriptive evidence packets and retains exact-FID legacy packet reads. Registration remains a pre-existing FID-named report handoff; operator submission changes generate/remove navigation without moving evidence. Sync skips canonical D-number packet artifacts, but still imports raw reports. Dynamic validation's packet lookup and lifecycle scan follow the ledger pointer. Standalone Bunny and profile-local finding-ingestion skills contain the requested one-line-paragraph instruction and ledger-resolved packet guidance; BBH's security-reporting, root card, and bounty-notes examples align.

Provider feature tip `c374c4511472401e2362569e6c800f8c5f94da5e` fixes initial review blockers, source/normalized and bulk-refresh retry traps, and interrupted scaffold publication. **Local source-contract smoke only, not installed provenance or an integrated release.**

## Evidence and review

- Baseline: `python3 -m pytest agents/test_finding_report.py agents/test_manual_hunter.py -q` — 38 passed, 13 subtests passed on fetched origin/beta.
- Consumer RED: descriptive path + submission E2E tests in `agents/test_finding_report.py` and `agents/test_manual_hunter.py` failed on old FID-only provider; provider source-contract smoke now passes their focused suites.
- Consumer local contract smoke: `PYTHONPATH=<provider-feature-worktree>:<BBH-feature-worktree> python3 -m pytest agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_dynamic_validation.py agents/test_report_checker.py agents/test_base_team_review.py -q --tb=short` — **131 passed, 13 subtests passed** with corrected provider. The new actual CLI-process E2E (`test_cli_packet_lifecycle_keeps_stable_path_and_submission_view`) was RED against old installed/source Core (`D01` vs descriptive packet) and GREEN against the provider feature. This still is not installed-pinned proof.
- Provider complete `python3 -m pytest -q --tb=short` — **183 passed**, including bulk ledger-failure retry and interrupted scaffold-publication regressions; third independent re-review pending.
- Broad `agents/` suite collected 2,360 tests. First `-x -vv` captured a stale FID-only expectation in AppMap E2E (185 passed, 1 failed); next `-x -q` captured a stale base-team packet-parent assertion (235 passed, 1 failed). Both were updated to assert the generated descriptive packet/ledger pointer. A subsequent foreground run reached ~20% before its 180-second tool limit; other background attempts returned host environment errors (`GOROOT` refers to absent `/usr/local/go`; Linuxbrew Python 3.14 lacks pytest) before a usable pytest summary. **Full agents/ suite is not green.**
- BBH focused source-contract suites plus full AppMap/base-team-ledger files: **240 passed, 13 subtests passed**. Actual CLI create/register/submit/drop passes in disposable root; repeat under checkout-local installed immutable pin before acceptance.
- Merge/ancestry evidence: feature based on fetched `origin/beta` 0e6fbc95d7f22c51f04eced826d31f21f7ac259b.

## Blockers and deferred work

- **Missing test or evidence:** Independent provider re-review, then installed immutable provider pin provenance and the actual CLI end-to-end cycle under that environment.
- **Command / fixture / environment needed:** publish provider beta; update manifest to full SHA, run `./setup.sh --install-python-deps` in BBH worktree, inspect installed `direct_url.json` and run focused plus CLI E2E suite with `.venv/bin/python`.
- **Trigger to run it:** provider reviewer accepts correction, provider beta is published and pinned.
- **Why it blocks integration, activation, or promotion:** source-only tests pass, but the checkout-local installed dependency and runtime have not been verified.
- **Next completion step / successor reference:** provider re-review; publish beta; pin/install BBH; installed E2E; independent BBH review; beta integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** `420ef2dd2aafa485d15bebefec0b4d5ee547e614`
- **Feature implementation commit(s):** `16fdd0e2932a7fde127a1234742e088f0d34979f`, `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`, `252a2e6131cf84a134d98ce0304c4b660b6f9bbb`, `420ef2dd2aafa485d15bebefec0b4d5ee547e614`
- **Exact resume point:** receive independent provider re-review, then publish provider beta, pin/reinstall BBH, and run installed full E2E.
- **Working-tree state at handoff:** task-owned BBH reconciliations committed as checkpoint; verify status before further edits.

## Decision gates

- **Integration gate:** provider published/pinned, consumer tests and independent review pass, current beta reconciled.
- **Activation / cohort gate:** verify installed dependency and synchronized Bunny/BBH skill content in selected runtime.
- **Promotion gate:** none requested; stable is separate.

## Decision record

- 2026-10-13 — created BBH feature worktree and recorded baseline; provider implementation delegated in separate repository.
