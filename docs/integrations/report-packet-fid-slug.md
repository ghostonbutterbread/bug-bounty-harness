# Finding packet layout integration dossier

- **Status:** feature
- **Owner:** Hermes / t_f9946642
- **Branch:** `feat/report-packet-fid-slug-tf9946642`
- **Base commit:** `0e6fbc95d7f22c51f04eced826d31f21f7ac259b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `/home/ryushe/.hermes/plans/2026-10-13_152453-report-packet-layout.md`; Bounty Core provider branch `feat/report-packet-fid-slug-tf9946642`.

## Intent

Consume Bounty Core's stable FID-and-vulnerability-slug packet path, retain exact FID final-report registration, and route BBH skills to the resolved evidence packet. Prove all behaviors without contacting a target or mutating production Shared data.

## Implemented contract

Pending Bounty Core provider implementation and frozen interface. The existing BBH beta still uses an exact FID packet.

## Evidence and review

- Baseline: `python3 -m pytest agents/test_finding_report.py agents/test_manual_hunter.py -q` — 38 passed, 13 subtests passed on fetched origin/beta.
- Consumer RED: descriptive path + submission E2E tests in `agents/test_finding_report.py` and `agents/test_manual_hunter.py` fail on old FID-only packet (expected); provider not yet available.
- Consumer GREEN: `python3 -m pytest agents/test_dynamic_validation.py::test_lifecycle_ingest_reads_descriptive_packet_from_ledger agents/test_dynamic_validation.py::test_report_ingest_accepts_ledger_bound_descriptive_packet agents/test_dynamic_validation.py::test_lifecycle_ingest_includes_evidence_only_packet_and_final agents/test_dynamic_validation.py::test_report_ingest_accepts_registered_fid_packet_paths -q` — 4 passed. New tests were observed RED before patching the report-ingest consumer.
- Sync baseline: `python3 -m pytest agents/test_sync_reports.py -q` — 26 passed.
- Independent review: pending.
- Fixture E2E: pending.
- Merge/ancestry evidence: feature based on fetched `origin/beta` 0e6fbc95d7f22c51f04eced826d31f21f7ac259b.

## Blockers and deferred work

- **Missing test or evidence:** Installed Bounty Core provider release and BBH pin provenance plus new packet end-to-end CLI cycle.
- **Command / fixture / environment needed:** local isolated root, BBH installer, provider release SHA, focused and adjacent pytest suite.
- **Trigger to run it:** provider branch passes tests and independent review, beta is published.
- **Why it blocks integration, activation, or promotion:** source-only provider edits do not reach BBH's installed dependency.
- **Next completion step / successor reference:** adapt BBH consumer and skills, rerun tests, independent review, beta integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** wait for provider contract, add failing consumer E2E first.
- **Working-tree state at handoff:** intentionally uncommitted dossier while active.

## Decision gates

- **Integration gate:** provider published/pinned, consumer tests and independent review pass, current beta reconciled.
- **Activation / cohort gate:** verify installed dependency and synchronized Bunny/BBH skill content in selected runtime.
- **Promotion gate:** none requested; stable is separate.

## Decision record

- 2026-10-13 — created BBH feature worktree and recorded baseline; provider implementation delegated in separate repository.
