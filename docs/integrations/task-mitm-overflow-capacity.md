# Task MITM bounded overflow integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix task `t_083f0962`
- **Branch / owning ref:** `fix/task-mitm-overflow-capacity-20261006`
- **Base commit:** `a9d625d39f247a9b708401056938533613419bae`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Latest immutable recovery checkpoint:** none yet (set after implementation commit)
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** read-only Hoster task-proxy investigation and `PC` proxy-capacity backlog in `Shared/PAPERCUTS.md`; `browser_provisioner.py` owns allocation.

## Intent

At the October 6 read-only inspection all ten task-proxy reservations in 8081–8090 were running, with no authoritative task-terminal proof for their old owners. New tasks receive `proxy-unavailable`; reclaiming quiet rows would risk ongoing replay. Add five bounded candidate ports instead of deleting or taking over any reservation. This is temporary admission relief, not a fix for missing durable task-terminal receipts.

## Implemented contract

Task proxy allocation considers 8081–8095 in order; 8091–8095 are overflow beyond the standalone lane lease defaults. It still skips reserved and listening ports, retains the same transaction and unit readiness checks, and does not reclaim or stop existing proxies. The skill states the updated task-proxy range; standalone lane lease defaults remain 8081–8090. No listener or proxy is started by integration itself.

## Evidence and review

- RED: isolated regression with 10 reserved rows failed `proxy-unavailable` at base range.
- GREEN: `agents/test_browser_provisioner.py agents/test_browser_lifecycle.py agents/test_mitm_lane.py` — 47 passed, 2 skipped (October 6, feature worktree using beta venv); `git diff --check` clean.
- Regression checks selection of 8091, skipping an occupied 8091 for 8092, and retention of all 10 original reservations without stopping old units.
- Hoster read-only preflight: no listeners on 8091–8110 at inspection, and no active Proxy Store leases on candidate ports. Recheck before any operational activation; the snapshot is not a durable exclusivity proof.
- Independent review: pending.
- Merge/ancestry evidence: feature started at fetched beta `a9d625d`; re-fetch/reconcile before merge.

## Blockers and deferred work

- **Missing test or evidence:** live Hoster admission and proxy readiness on a new owned task; not needed to merge source, required to call the capacity issue operationally relieved. Recheck listeners and leases first; run only an owned task through normal provisioning when available.
- **Missing durable repair:** old ownerless rows cannot be released from age or inactive browser status. Wire supervisor-issued terminal receipt after direct replay, and fence exact run before reaping; separately verify owner lifecycle. This change does not retroactively prove terminality.
- **Reservation coordination:** custom standalone lane leases can choose non-default ports. Socket checks prevent reuse of a live listener, but do not guarantee exclusivity against a future manually configured lease. Review this risk before beta integration; do not claim the overflow is an authoritative separate namespace.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/task-mitm-overflow-capacity-20261006`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit feature, record checkpoint, get independent review of allocator bounds, cross-lease race, negative paths, and feature ancestry; reconcile beta if it advances.
- **Working-tree state at handoff:** changes pending first commit.

## Decision gates

- **Integration gate:** independent review of the exact diff/dossier and focused regression; current fetched beta ancestry.
- **Activation / cohort gate:** check selected Hoster runtime and candidate ports/lease stores anew; confirm no shared in-progress task is interrupted. No service stop/restart or old-row cleanup.
- **Promotion gate:** separate main-lane decision and runtime receipt; not implied by beta merge.

## Decision record

- 2026-10-06 — created a bounded bridge for exhausted task-MITM capacity; no old reservation was changed.
