# Legacy profile history integration dossier

- **Status:** feature; independent review counterexample repaired, pending re-review
- **Owner:** bugfix subagent
- **Branch / owning ref:** `fix/legacy-profile-history-20261019`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness-legacy-profile-history-20261019` (Hoster)
- **Base commit:** `9f56eb16d480eda212f7f76108a329d434aa9d9a`
- **Intended integration target:** `origin/beta` / `beta`
- **Last updated:** 2026-10-19
- **Latest immutable recovery checkpoint:** `b7c1b5d` (prior implementation; this follow-up commit supersedes its review state)
- **Feature implementation commit(s):** `b7c1b5d` plus cross-alias repair at this branch tip (SHA reported externally; self-SHA cannot be embedded)
- **Inspiration:** terminal pre-manager `manager_id=NULL` named-account `--recover-profile` lock; PC-20261002-194658-450fe6f0.

## Intent and implemented contract

A manager-proven stopped unkeyed profile can be reacquired when canonical history includes older pre-manager NULL-manager leases, but only where each such row has the same physical profile and exact auth domain, terminal `released`/`expired` status, `browser_status=stopped`, and no CDP URL. The selected source still requires matching non-NULL manager ID, exact lease/owner/path, and released status; foreign-account, foreign-program, foreign-domain, or keyed history sharing that physical directory (including symlink aliases) denies inheritance at the acquisition transaction. Distinct physical profiles remain eligible. Provisioner still checks manager row and quiescence before calling acquire. A foreign manager, active NULL-manager history, uncertain released browser, CDP evidence, profile/domain divergence, or unverifiable source remains locked. No historic row is rewritten, and `browser_manager_row_repair.py` still owns only malformed manager projections; it does not repair canonical lease-manager provenance.

## Evidence and review

- RED: `agents/test_browser_legacy_auto.py -k pre_manager_history` had released and expired NULL-manager histories locked; active case locked.
- GREEN: `TMPDIR=/home/ryushe/.cache/bbh-legacy-profile-pytest /home/ryushe/projects/bug_bounty_harness-runtime-beta-coverage-20261016/.venv/bin/python -m pytest agents/test_browser_legacy_auto.py agents/test_browser_manager_row_repair.py agents/test_browser_profile_lease.py agents/test_browser_lease_recovery.py -q` → 118 passed (including CDP/unverified negatives).
- Independent review found a cross-alias physical-profile takeover: active foreign-manager symlink lease plus terminal NULL-manager source-alias history was admitted. New disposable regression RED (2 failures: both active/running and released/uncertain foreign aliases returned `leased`), GREEN (3 passed including distinct physical profile positive). Foreign physical ownership is checked inside the acquire `BEGIN IMMEDIATE` transaction.
- Focused post-fix suites: `TMPDIR=/home/ryushe/.cache/bbh-legacy-profile-pytest /home/ryushe/projects/bug_bounty_harness-runtime-beta-coverage-20261016/.venv/bin/python -m pytest agents/test_browser_legacy_auto.py agents/test_browser_manager_row_repair.py agents/test_browser_profile_lease.py agents/test_browser_lease_recovery.py -q` → 121 passed in 15.98s; `git diff --check` clean. Fetched `origin/beta` remains `9f56eb1` (merge base).
- Fixture is disposable SQLite/profile under pytest's temp root; no live lease DB/profile/unit accessed.
- Independent re-review: pending parent/release reviewer; no integration or push authorized.
- Merge/ancestry: feature starts at fetched `origin/beta` `9f56eb1`; beta advancement must be checked before review.

## Blockers and deferred work

- **Missing evidence:** live Hoster named-account recovery; intentionally not attempted against live state.
- **Trigger:** separately authorized maintenance window after independent review, with verified stopped manager row and owner/quiescence.
- **Why:** source manager identity and `browser_status=stopped` are metadata assertions, not independent proof that an old browser is truly absent; provisioner's quiescence remains the runtime fence.
- **Next:** reviewer replays focused tests and audits selected source and historical rows before beta integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/legacy-profile-history-20261019`
- **Latest immutable recovery checkpoint:** `b7c1b5d`; new follow-up commit at branch tip must be verified separately.
- **Feature implementation commit(s):** `b7c1b5d` and follow-up commit at branch tip.
- **Exact resume point:** independent re-review of physical-profile boundary and current beta ancestry; no merge/push.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration:** independent portable review and current-beta reconciliation required.
- **Activation:** no live state change; beta integration is not deployment.
- **Promotion:** not authorized.

## Decision record

- 2026-10-19 — independent review counterexample reproduced, physical cross-alias admission boundary repaired, focused tests pass; awaiting re-review.
