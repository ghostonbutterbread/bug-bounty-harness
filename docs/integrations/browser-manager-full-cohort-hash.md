# Browser manager full-cohort repair-plan integration dossier

- **Status:** review-ready (code only; live repair remains blocked)
- **Owner:** Hermes, Kanban `t_b22644ac`
- **Branch / owning ref:** `fix/browser-manager-full-cohort-hash`
- **Worktree:** `/home/ryushe/worktrees/bbh-browser-manager-full-cohort-hash`
- **Base commit:** `d077b8971b3e87fbd1278f4874cd53399564b74f`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-24
- **Latest immutable recovery checkpoint:** `54acfd98adb30521ede3a03cd654a030e07264c4`
- **Feature implementation commit:** `54acfd98adb30521ede3a03cd654a030e07264c4`
- **Inspiration:** Historical browser repair review `t_a4757067/REVIEW.md`; prior partial repair `t_837ef9ae`.

## Intent

Ensure exact-program/account historical manager-row repair refuses an approved plan if any selected-cohort manager row or exclusion changes. This does not loosen runtime quiescence gates, clear Chromium locks, touch canonical leases, or authorize a live Hoster apply.

## Implemented contract

The plan hash now covers the selected program/account, every manager row's lease ID and complete row digest (including non-candidates), blocked reason map, and the existing candidate projection/evidence. Apply recomputes under the node lock and attached-database `BEGIN IMMEDIATE` before conditional updates. The receipt adds `observed_count`. Existing paired private backups remain mandatory. Rows outside the exact cohort do not enter this hash; physical-alias ownership checks still scan active canonical leases globally.

## Evidence and review

- `python -m pytest -q agents/test_browser_manager_row_repair.py agents/test_browser_legacy_auto.py` → 75 passed locally.
- `git diff --check` → clean.
- Independent review of `54acfd9` approved code integration against `d077b89`; reviewer reran repair suite twice (23/23), confirmed excluded-row and blocker-reason mutation tests, and made no edits or Hoster DB access. The broader lease-recovery run timed out; not claimed passed.
- `origin/beta` fetched 2026-09-24 and remained `d077b8971b3e87fbd1278f4874cd53399564b74f`.

## Blockers and deferred work

- **Live apply:** Prior operational NO-GO still applies. Missing per-row browser/profile owner and quiescence evidence, manager/watcher launch fencing, exact-cohort runtime plan compared immediately before apply, and reviewed private backup/readback procedure. Run `browser_manager_row_repair.py --manager-db <node-state> --program <p> --account <a> --probe-runtime` on Hoster only after the relevant launch paths are fenced; review its full cohort/count/exclusions before supplying that hash to an exact apply. Trigger: operator-approved quiescence and independently reviewed per-cohort evidence. No bulk or lock-blocked repair is approved by this code change.
- **Chrome SingletonLock unlink:** Separate profile mutation, not covered or authorized here; requires distinct mechanism, proof and review.
- **Broader lease-recovery tests:** Independent review timed out; rerun in integration/runtime when resources allow, not a claimed pass.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-manager-full-cohort-hash`
- **Latest immutable recovery checkpoint:** `54acfd98adb30521ede3a03cd654a030e07264c4`
- **Feature implementation commit:** `54acfd98adb30521ede3a03cd654a030e07264c4`
- **Exact resume point:** Record dossier and independent approval in a commit; merge into clean fetched `beta`, remove temporary dossier from integration target, rerun focused suite, push/read back `beta`; only then consider Hoster rollout. No live DB apply without a separate GO.
- **Working-tree state at handoff:** This dossier is being committed before integration.

## Decision gates

- **Integration gate:** Independent code review approved, focused tests passed; track dossier then integrate to beta with tests and remote readback.
- **Activation/cohort gate:** New runtime bits deployed and exact per-cohort safety evidence/review; code integration alone is not a live-apply GO.
- **Promotion gate:** Stable/main requires separate direction and review.

## Decision record

- 2026-09-24 — Full-cohort hash implemented and tested; independent code review approved with a missing tracked dossier process gap, now resolved by this record. Live cleanup NO-GO remains.
