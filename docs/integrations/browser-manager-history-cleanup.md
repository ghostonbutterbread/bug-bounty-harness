# Browser manager historical row cleanup integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch:** `fix/browser-manager-history-cleanup`
- **Base commit:** `7690fc04e1a539c50013b119cc4a49f3082032f5`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-24
- **Owning feature branch/ref:** `fix/browser-manager-history-cleanup`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** user request to repair Hoster shifted historical manager rows and normalize idle-stopped; browser-runtime-operations lifecycle repair constraints.

## Intent

Repair only exact historical positional-shift rows and ordinary idle-stopped rows under an exact program/account selection. Do not change canonical leases, profiles, live browsers, or unrelated programs. Keep cross-program physical alias protection.

## Implemented contract

Read-only plan can run apply-time liveness probes. Gated apply requires plan hash, explicit terminal-owner confirmation, private backup directory, node lock, two-DB transaction, exact row identity, terminal canonical lease (released/expired), inactive service/owner/root, no profile lock/process/CDP, and no active physical-alias lease. Reconstructed shifted and verified idle-stopped manager states normalize to stopped. Ambiguous rows remain quarantined. An expired lease alone is not termination proof. Backup both databases before any manager change. No global blind rewrite.

## Evidence and review

- Tests: `python3 -m pytest agents/test_browser_manager_row_repair.py agents/test_browser_legacy_auto.py -q` → 70 passed; `git diff --check` clean.
- Independent review: pending.
- Live read-only inventory: 401 rows, 236 shifted across six programs (176 released, 60 expired); 10 idle-stopped across two programs (eight expired, two released). Two active Neon browser units were seen; do not interrupt them.

## Blockers and deferred work

- **Missing evidence:** per-cohort Hoster read-only runtime-probed plan and owner quiescence; live applies are not authorized by a mere expiry status.
- **Command/environment:** beta Hoster `.venv/bin/python skills/chromium-test/scripts/browser_manager_row_repair.py --manager-db ~/.local/state/ghost/browser-profile-leases/browser_provisioner.sqlite --program PROGRAM --account ACCOUNT --probe-runtime` after reviewed beta rollout. Before apply, verify exact selected cohort's watcher/owner inactivity; supply plan hash, private backup directory and explicit confirmation. Read back state and active units afterward.
- **Trigger:** independent review approval and clean beta runtime deployment; if any target owner remains active, quarantine it until normal release.
- **Why:** historical state write may otherwise alter an active browser's ownership projection.
- **Next completion step:** review, integrate, deploy, plan each cohort, apply only proven candidates, verify residual blockers.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-manager-history-cleanup`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** final focused review of current diff and live plan; then beta integration/Hoster activation.
- **Working-tree state at handoff:** intentionally uncommitted pending review.

## Decision gates

- **Integration gate:** independent review of exact-row safety + tests.
- **Activation / cohort gate:** active beta checkout clean; private backup pair; per-cohort live terminal proof.
- **Promotion gate:** separate owner direction.

## Decision record

- 2026-09-24 — began generalized terminal-history repair; active Neon owner untouched.
