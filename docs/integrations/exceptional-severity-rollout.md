# Exceptional severity rollout integration dossier

- **Status:** review-ready
- **Owner:** Hermes (Ryushe-directed)
- **Branch:** `feat/exceptional-severity-rollout`
- **Base commit:** `9fad5f4` (beta tip, fetched — includes upstream blind-xss merge)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-18
- **Owning feature branch/ref:** `feat/exceptional-severity-rollout` (worktree `~/projects/bbh-feat-exceptional-rollout`)
- **Latest immutable recovery checkpoint:** none yet (commit pending)
- **Feature implementation commit(s):** none yet
- **Upstream dependency:** bounty-core `201a47f7afff1db1b592f5d7126e7717d1feb171` (v0.2.0, EXCEPTIONAL severity, pushed to bounty-core beta, independently reviewed PASS 2026-09-18)

## Intent

P0 is Ryushe's exceptional severity: a distinct top tier ABOVE critical, not
equal to it. bounty-core 0.2.0 adds the `EXCEPTIONAL` enum member
(`P0 → EXCEPTIONAL`, sorts first). This branch rolls the harness onto it:
re-pin, and fix the one consumer the reviewer flagged that would have
degraded EXCEPTIONAL to UNKNOWN.

## Implemented contract

1. `requirements.txt` pin: bounty-core `62a8b6f` → `201a47f` (v0.2.0).
2. `agents/manual_hunter.py`:
   - `SEVERITIES` set gains `EXCEPTIONAL` (used by report templates/prompt text).
   - `_normalize_severity` now delegates to `bounty_core.finding.normalize_severity`
     instead of local set membership — one source of truth, so note values like
     `P0`, `P1`, `p2`, `critical` normalize identically to the `me_ledger add`
     path. Interactive prompt text updated to include EXCEPTIONAL.
3. `skills/ledger/SKILL.md`: severity note now documents P0 = exceptional top
   tier above CRITICAL.
4. New regression test: note severity values (P0/P1/p2/critical/bogus) parse
   to canonical enum through manual_hunter's parse path.

Behavior verified live: `Severity: P0` note → ledger stores `EXCEPTIONAL`;
`--severity P0` via me_ledger → `EXCEPTIONAL`; P1→CRITICAL; garbage→UNKNOWN.

## Evidence and review

- Tests and commands:
  - Focused suite: 51 passed, 17 subtests (`agents/test_me_ledger.py`,
    `test_manual_hunter.py`, `test_ledger_v2.py`,
    `test_ledger_v2_compatibility_fixtures.py`, `test_finding_visibility.py`).
  - Live smoke: manual_hunter `--from-file` with `Severity: P0` → ledger
    entry carries `severity: EXCEPTIONAL` + scoring fields.
  - bounty-core upstream review: PASS (2026-09-18, exhaustive severity-site
    sweep, 6/6 steps; transcript
    `/home/ryushe/.hermes/cache/delegation/live/deleg_e283bf37/task-0.log`).
- Independent review: pending (required before beta merge).
- Merge/ancestry evidence: branch from fetched beta tip `9fad5f4`.

## Blockers and deferred work

None blocking. Notes:
- bounty-core SEVERITY_GROUPS retains an always-empty EXCEPTIONAL entry
  (reviewer: dead-but-harmless; grouped indexes render an empty section
  consistent with existing empty-group behavior).
- Hoster picks up EXCEPTIONAL at its next manifest re-sync (deliberate).

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/exceptional-severity-rollout`
- **Latest immutable recovery checkpoint:** none yet — commit before pause.
- **Feature implementation commit(s):** none yet.
- **Exact resume point:** commit, delegate release-gate review, merge to beta.
- **Working-tree state at handoff:** intentionally uncommitted (tests + live
  smoke verified 2026-09-18).

## Decision gates

- **Integration gate:** independent review PASS required before beta merge.
- **Activation / cohort gate:** venvs re-sync from manifest; skill text flows
  via aiskillsync projection.
- **Promotion gate:** standard main promotion, not requested.

## Decision record

- 2026-09-18 — created; implementation verified (tests + live smoke), commit
  pending.
- 2026-09-18 — commit `708e699`; independent review FAIL: report_checker.py
  SEVERITY_ORDER rejected EXCEPTIONAL (view layer degraded to UNKNOWN).
- 2026-09-18 — blocker fixed: report_checker SEVERITY_ORDER gains EXCEPTIONAL
  (rank above CRITICAL) and _normalize_severity delegates to bounty_core;
  report_generator SEVERITY_ORDER gains EXCEPTIONAL; regression test added
  (test_report_checker_exceptional.py). Pre-existing test_sync_reports
  failures verified unrelated (fail identically on clean beta). Re-review
  pending.
