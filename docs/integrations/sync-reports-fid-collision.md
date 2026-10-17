# Sync reports FID collision integration dossier

- **Status:** blocked for integration review
- **Owner:** Hermes bugfix reconciliation
- **Branch / owning ref:** `fix/sync-reports-fid-collision`
- **Worktree:** `/home/ryushe/worktrees/bbh-sync-reports-fid-collision`
- **Base commit:** `388e0929718405ca826b8abbd14235e4c3dfc23b` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-16
- **Latest immutable recovery checkpoint:** none yet; the forthcoming feature commit carries this dossier and implementation
- **Feature implementation commit(s):** forthcoming feature commit
- **Inspiration:** Hoster active runtime `/home/ryushe/projects/bug_bounty_harness-runtime-beta-reporting-20261013` at `5770784e1e07d990c4bb592fdad6217118222666`, dirty diff limited to `agents/sync_reports.py` and `agents/test_sync_reports.py`; Hoster checkout untouched.

## Intent and implemented contract

Port the Hoster repair to current published beta without changing the dirty runtime: catch a `ValueError` raised by `hunter.ledger.check(candidate)` during report import, skip that candidate, emit stderr and summary reconciliation diagnostics, continue to subsequent candidates, and return nonzero. Add a focused mock regression for this branch. No automatic FID reassignment, report mutation, merge, push, or runtime switch.

## Evidence and review

- Focused test: `python3 -m unittest agents.test_sync_reports.TestSyncReports.test_sync_report_fid_collision_is_skipped_and_reported` passed.
- Adjacent tests: `python3 -m unittest agents.test_sync_reports agents.test_report_checker agents.test_report_checker_exceptional` passed (50 tests).
- `git diff --check` passed.
- A broader attempted run included nonexistent `agents.test_report_paths` and the already failing `agents.test_finding_report.BunnyReportRegistrationTests.test_provider_pin_is_accepted_evidence_only_revision`; the latter reproduces on clean beta because its expected Bounty Core pin differs from `requirements.txt`. Neither is fixed here.
- Base ancestry: Hoster `5770784` is an ancestor of current `origin/beta` `388e092`; both changed script/test files were unchanged between those commits.

## Blockers and deferred work

- **Missing evidence:** A real FID collision delivered from the current `FindingsLedger.check` to this exception handler. The current `agents/findings_ledger.py` implementation of `check` uses the candidate fingerprint, reserves a newly generated FID, and does not itself reject an already-supplied different FID; the regression injects a `ValueError` via Mock. Review whether the observed Hoster failure actually arises downstream in `update_team_finding`, or from another runtime ledger implementation, before integrating or activating. Reproduce with an owned temporary ledger and report using `python3 -m unittest agents.test_sync_reports` plus a realistic ledger collision fixture; if the throw site is downstream, the repair needs a deliberate change rather than silently claiming end-to-end coverage.
- **Independent review:** Not performed in this isolated feature task; reviewer should inspect the exception boundary, report safety, and the above fixture before merging.
- **Existing unrelated test failure:** `python3 -m unittest agents.test_finding_report.BunnyReportRegistrationTests.test_provider_pin_is_accepted_evidence_only_revision` fails on clean beta and feature due to an outdated expected dependency pin. Handle separately.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/sync-reports-fid-collision`
- **Latest immutable recovery checkpoint:** forthcoming feature commit (inspect branch tip after commit)
- **Feature implementation commit(s):** forthcoming feature commit
- **Exact resume point:** independently review actual throw site and run an unmocked collision fixture; then decide whether to revise this feature or reject it. Do not merge until resolved.
- **Working-tree state at handoff:** clean after planned commit.

## Decision gates

- **Integration gate:** blocked on unmocked reproduction and independent review; user explicitly forbids merge/push.
- **Activation / promotion gate:** not requested; Hoster active runtime remains untouched.

## Decision record

- 2026-10-16 — reconciled the Hoster diff into an isolated beta-based feature, added output assertions and corrected mock side-effect annotation. Kept integration blocked pending real throw-site evidence.
