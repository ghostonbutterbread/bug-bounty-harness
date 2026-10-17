# Live Coverage review vocabulary integration dossier

- **Status:** feature (uncommitted handoff; parent owns integration)
- **Owner:** task t_e0602952 / parent agent
- **Branch / owning ref:** `fix/coverage-review-vocabulary-te0602952`
- **Worktree:** `/home/ryushe/worktrees/bbh-coverage-vocabulary`
- **Base commit:** `7fd8abbdd0c7abd1cd58b854ad3e0dcebefd82d6` (`origin/beta` fetched during task)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-16
- **Latest immutable recovery checkpoint:** none; delegated task explicitly forbids commit
- **Feature implementation commits:** none; delegated task explicitly forbids commit
- **Canonical owner:** `agents/surface_coverage.py`, `agents/coverage.py`, `skills/coverage/SKILL.md`
- **Supersedes:** live Coverage status wording only; not the static `coverage.json` contract or XSS specialist pressure

## Intent and implemented contract

Live mapped surface/class discovery now writes and presents `no_assessment`; reviewed paths use `bounded_review`, scoped to an exact surface/class/version with reason, boundary, axes, and evidence pointers. This label does not assert absence of a vulnerability, closure of sibling paths, or XSS specialist exhaustion. `in_progress`, `blocked`, and `stale` remain unchanged. XSS `pressure` is not translated.

Old SQLite `untested` and `exhausted` rows/history remain on disk and are translated in brief counts/items, history, and stale prior_status on read. New discoveries explicitly set `no_assessment` even when an existing SQLite table has the old default. New assessments store the canonical status; legacy `--status exhausted` remains a deprecated CLI and store input alias (same validation) and writes `bounded_review`. Both dedicated and `me_ledger.py surface-*` compatibility commands use the same parser. No destructive migration; `coverage.json` is untouched.

## Evidence and review

- Failing-first receipt: `python -m unittest agents.test_surface_coverage.SurfaceCoverageTests.test_old_sqlite_rows_and_history_read_as_narrow_review_without_rewrite agents.test_surface_coverage.SurfaceCoverageTests.test_new_discovery_and_review_write_canonical_statuses agents.test_surface_coverage.SurfaceCoverageTests.test_bounded_review_requires_exact_boundary_axes_and_evidence -v` → 3 expected failures (`exhausted` and `untested` visible). After store fix → 3 passed.
- CLI failing-first: `python -m unittest agents.test_coverage_cli.CoverageCliTests.test_both_cli_names_accept_new_and_legacy_review_alias_with_canonical_output -v` → expected argparse invalid choice `bounded_review`; after parser fix → passed.
- Focused suite: `python -m unittest agents.test_surface_coverage agents.test_coverage_cli -v` → 37 passed; re-run after adding explicit XSS pressure preservation: `python -m unittest agents.test_surface_coverage agents.test_coverage_cli -q` → 37 passed.
- `git diff --check` → clean. Bounded reference audit of `coverage.py` and `surface_coverage` consumers found only the intentionally retained old input alias, SQLite read mapping, compatibility tests and unchanged static `coverage.json` fixture; `/coverage`, `/xss`, and `/api-surface-mapping` live discovery guidance updated. Other `untested` and `exhausted` terms refer to separate stores, hypotheses or specialist pressure and remain unchanged.
- Independently reviewed: **approved** read-only review against this uncommitted diff. Reviewer ran 24 store tests and 13 CLI tests separately, both passed; combined invocation timed out. `git diff --check` clean. No reviewer edits.
- Fixture evidence: temporary SQLite old rows and history, stale fingerprint and mapper-run transitions, static coverage.json byte preservation, CLI subprocess aliases, XSS pressure separation.

## Blockers and deferred work

- **Missing evidence:** beta merge/release integration and Hoster runtime activation checks.
- **Trigger / command:** after approved feature commit, reconcile latest `origin/beta`, run integrated focused tests and a no-write old-DB brief, then activate selected Hoster beta runtime and read back exact revision/skill projection.
- **Why:** review approved local behavior, not a published or active runtime; Hoster's stored old statuses must remain readable.
- **Next step:** parent commits reviewed feature, merges to clean current beta, verifies and publishes, then separately validates Hoster activation.

## Interruption / resume handoff

- **Owning ref:** `fix/coverage-review-vocabulary-te0602952`
- **Recovery checkpoint:** none (explicit no-commit instruction)
- **Resume:** inspect uncommitted diff, independently review, then parent controls commit/integration.
- **Working tree:** intentionally uncommitted per task boundary.

## Decision gates

- **Integration:** focused tests and reference audit, fresh diff review and parent authorization.
- **Activation:** selected runtime must consume merged `beta` after owner verification.
- **Promotion:** no stable promotion authorized.

## Decision record

- 2026-10-16 — Branch-local correction, test-first compatibility mapping; no release decision.
