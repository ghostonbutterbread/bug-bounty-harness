# Sync reports FID collision integration dossier

- **Status:** real ledger collision reproduced in isolated storage; independent review approved, beta integration and Hoster activation pending
- **Owner:** Hermes bugfix reconciliation
- **Branch / owning ref:** `fix/sync-reports-fid-collision`
- **Worktree:** `/home/ryushe/worktrees/bbh-sync-reports-fid-collision`
- **Base commit:** `388e0929718405ca826b8abbd14235e4c3dfc23b` (fetched `origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-16
- **Latest immutable recovery checkpoint:** `fe3cbc6ae8d61d792972e751c364f24b1cb4998c` (real-ledger fixture and handoff)
- **Feature implementation commit(s):** `063dd509ff8fd30606dee250b49bb13093e36196`, `fe3cbc6ae8d61d792972e751c364f24b1cb4998c`
- **Inspiration:** Hoster active runtime `/home/ryushe/projects/bug_bounty_harness-runtime-beta-reporting-20261013` at `5770784e1e07d990c4bb592fdad6217118222666`, dirty diff limited to `agents/sync_reports.py` and `agents/test_sync_reports.py`; Hoster checkout untouched.

## Intent and implemented contract

Port the Hoster repair to current published beta without changing the dirty runtime: catch a `ValueError` raised by `hunter.ledger.check(candidate)` during report import, skip that candidate, emit stderr and summary reconciliation diagnostics, continue to subsequent candidates, and return nonzero. Retain the focused mock regression and add an isolated real-ledger collision fixture. No automatic FID reassignment, merge, push, or runtime switch.

## Evidence and review

- Real-ledger fixture: `agents.test_sync_reports.TestSyncReports.test_real_ledger_fid_collision_continues_import_and_returns_nonzero` seeds `D06` through unmocked `bounty_core.ledger.VersionedFindingsLedger.check` into `TemporaryDirectory` storage; a second identity (`src/different.js`) carrying `D06` raises the actual `ValueError("finding FID already assigned: D06")`. `sync_reports_main` uses a real `ManualHunter`/ledger and real `update_team_finding`; only parsing and chain suggestions are patched. It reports the collision, persists the next independent `D07`, keeps original `D06` unchanged, and exits 1. Focused test passed under beta `.venv` with Bounty Core pin `6c36ee88a60073e1b687ec32deeade24ffafdd4f`.
- Focused mock test: `agents.test_sync_reports.TestSyncReports.test_sync_report_fid_collision_is_skipped_and_reported` passed previously.
- Adjacent tests: `/home/ryushe/worktrees/bbh-beta-coverage-release/.venv/bin/python -m unittest agents.test_sync_reports agents.test_report_checker agents.test_report_checker_exceptional` passed (51 tests) from feature worktree.
- `git diff --check` passed on the fixture/dossier revision.
- A broader attempted run included nonexistent `agents.test_report_paths` and the already failing `agents.test_finding_report.BunnyReportRegistrationTests.test_provider_pin_is_accepted_evidence_only_revision`; the latter reproduces on clean beta because its expected Bounty Core pin differs from `requirements.txt`. Neither is fixed here.
- Base ancestry: Hoster `5770784` is an ancestor of current `origin/beta` `388e092`; both changed script/test files were unchanged between those commits.

## Blockers and deferred work

- **Resolved throw-site question:** `ManualHunter.ledger` is `bounty_core.ledger.VersionedFindingsLedger`, constructed via `agents/ledger.py:create_team_ledger_from_storage`, not `agents/findings_ledger.py`. Its `check` calls Bounty Core `_reserve_candidate`; that function rejects a caller-supplied FID when `_find_existing` did not match and the FID belongs to another identity. The real-ledger fixture above proves this path before `update_team_finding`; no downstream-only hypothesis remains.
- **Independent review:** Approved read-only review at `fe3cbc6`; reviewer independently ran 51 adjacent tests and `git diff --check`. The handler labels all `check()` `ValueError`s as FID collisions, including invalid-FID errors; it still reports the underlying error and exits nonzero. A collision followed by a successful separate import is deliberately partial, not atomic—operators must account for the committed import on retry.
- **Existing unrelated test failure:** `python3 -m unittest agents.test_finding_report.BunnyReportRegistrationTests.test_provider_pin_is_accepted_evidence_only_revision` fails on clean beta and feature due to an outdated expected dependency pin. Handle separately.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/sync-reports-fid-collision`
- **Latest immutable recovery checkpoint:** `fe3cbc6ae8d61d792972e751c364f24b1cb4998c`; review decision is a later dossier-only commit.
- **Feature implementation commit(s):** `063dd509ff8fd30606dee250b49bb13093e36196`, `fe3cbc6ae8d61d792972e751c364f24b1cb4998c`.
- **Exact resume point:** merge accepted feature into clean current beta after fetching and checking ancestry, retire dossier, run integrated tests, publish beta; migrate Hoster to a clean selected checkout without altering the old dirty runtime.
- **Working-tree state at handoff:** verify clean after fixture/dossier commit.

## Decision gates

- **Integration gate:** independent review approved `fe3cbc6`; merge into `beta` after ancestry check and integrated test pass. Ryu explicitly chose reconciling this reporting behavior to enable Coverage activation.
- **Activation / promotion gate:** after beta publication, select a clean Hoster runtime, compare host-local configuration, preserve the dirty former source, and verify managed skill/launcher projections; no stable promotion.

## Decision record

- 2026-10-16 — reconciled the Hoster diff into an isolated beta-based feature, added output assertions and corrected mock side-effect annotation.
- 2026-10-16 — corrected ledger ownership, reproduced the Bounty Core collision in temporary storage through `sync_reports_main`, and retained independent review as the only integration evidence gate.
