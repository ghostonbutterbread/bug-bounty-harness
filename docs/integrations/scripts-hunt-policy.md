# Script-assisted hunting integration dossier

- **Status:** review-ready
- **Owner:** Hermes Agent
- **Branch:** `docs/scripts-hunt-policy`
- **Base commit:** `58706890ddb4cb4e882bbe781a4a9157a806dc5b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `docs/scripts-hunt-policy`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration:** Ryu's request for one BBH `/scripts` policy loaded when vulnerability hunters run scripts, rather than duplicated specialist-only wording or Script Manager obligations.

## Intent and contract

`skills/scripts/SKILL.md` owns bounded interpretation of script output and concurrent application-specific, vulnerability-class inquiry during longer runs. A short run gets its coverage review afterward. The BBH entry routes relevant hunt scripts to it; XSS and JS retain only class-specific examples and skill-local command discovery. `SCRIPT_POLICY.md` remains for creation/maintenance; no script executable or inventory implementation changes. Live policy and class proof gates stay authoritative. This is not a universal rule for tests, migrations, or all operations.

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_script_policy.py` (25 passed); `python3 -m pytest -q skills/xss/scripts/test_xss_canary_mapper.py` (15 passed); `git diff --check` clean. `python3 -m pytest -q tests` returned 183 passed, 1 skipped, 3 pre-existing failures in `test_hoster_script_authority.py`, `test_runtime_dependencies.py`, and `test_skill_command_lane_safety.py` (the latter names an unchanged dossier at base). Root-level `python3 -m pytest -q` additionally fails collecting `test_catalog.py` due to unavailable `bac_checks` import.
- Independent review: pending.
- Merge/ancestry evidence: pending fresh `origin/beta` reconciliation.

## Blockers and deferred work

- No known implementation blocker. Baseline suite failures above are not caused by this diff; rerun those tests when their owners reconcile the stale assertion, dependency pin, old dossier, and root-level import path. Hoster new-skill projection requires a clean beta runtime checkout, profile dry-run, apply, and active-link read-back; if remote credentials fail, preserve published source and report activation blocked rather than transferring via an unapproved fallback.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/scripts-hunt-policy`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit tested feature, obtain independent review, then integrate to `beta` and activate linked skill.
- **Working-tree state at handoff:** intentionally uncommitted implementation in task worktree before first checkpoint.

## Decision gates

- **Integration gate:** focused tests and independent review of one canonical owner and specialist routes.
- **Activation gate:** published beta revision, clean Hoster source update, focused profile sync and active-link content check.
- **Promotion gate:** main requires explicit Ryu direction; out of scope.

## Decision record

- 2026-10-06 — opened task-owned feature from fetched beta; owner proposed as `skills/scripts/SKILL.md`; focused tests passed; wider baseline failures recorded.
