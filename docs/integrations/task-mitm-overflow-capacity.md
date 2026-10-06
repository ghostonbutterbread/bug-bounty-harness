# Task MITM bounded overflow integration dossier

- **Status:** review-ready after blocker remediation; independent re-review pending
- **Owner:** Hermes bugfix task `t_083f0962`
- **Branch / owning ref:** `fix/task-mitm-overflow-capacity-20261006`
- **Base commit:** `a9d625d39f247a9b708401056938533613419bae`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Latest immutable recovery checkpoint:** `086ee51e32a834a21e286ccf302557c9452098f9`
- **Feature implementation commit(s):** `5c24dfee67fc6171d02b74ae66e2a664111ce818`, `086ee51e32a834a21e286ccf302557c9452098f9`
- **Inspiration / canonical references:** read-only Hoster task-proxy investigation and `PC` proxy-capacity backlog in `Shared/PAPERCUTS.md`; `browser_provisioner.py` owns allocation.

## Intent

At the October 6 read-only inspection all ten task-proxy reservations in 8081–8090 were running, with no authoritative task-terminal proof for their old owners. New tasks receive `proxy-unavailable`; reclaiming quiet rows would risk ongoing replay. Add five bounded candidate ports instead of deleting or taking over any reservation. This is temporary admission relief, not a fix for missing durable task-terminal receipts.

## Implemented contract

Task proxy allocation considers 8081–8095 in order; 8091–8095 are bounded overflow reserved against **both** default and custom Proxy Store standalone lease acquisition. Both scripts read the overflow bound from Proxy Store constants; an explicit standalone `--port` in the reserved range returns `task-port-reserved` (CLI exit 2) without creating a lease DB, and custom ranges skip reserved candidates. Before allocating overflow, the provisioner also reads active standalone leases from the local Proxy Store DB without writing it, skipping an older custom lease on 8091–8095 and failing closed if that store cannot be read. The allocator still skips task-reserved and listening ports, retains the same transaction and unit readiness checks, and does not reclaim or stop existing proxies. No listener or proxy is started by integration itself.

## Evidence and review

- RED: isolated regression with 10 reserved rows failed `proxy-unavailable` at base range.
- GREEN after reconciliation: `agents/test_browser_provisioner.py agents/test_browser_lifecycle.py agents/test_mitm_lane.py agents/test_proxy_store.py agents/test_hoster_mitm_lane.py` — 70 passed, 2 skipped (October 6, feature worktree using beta venv); `git diff --check` clean.
- Regression checks selection of 8091, skipping an occupied or pre-existing standalone-leased 8091 for 8092, and retention of all 10 original reservations without stopping old units.
- RED then GREEN: an explicit custom 8091 lease was granted before the guard; now rejected. A custom-only 8091–8095 range no longer grants a lease. CLI previously returned success for the new rejection status; now exits 2. The guard happens before any DB creation for explicit `--port`.
- Hoster read-only preflight: no listeners on 8091–8110 at inspection, and no active Proxy Store leases on candidate ports. Recheck before any operational activation; the snapshot is not a durable exclusivity proof.
- Independent review of first tip `6de8580`: **beta blocker**—Proxy Store granted a custom 8091 lease while allocator independently chose it. The current guard and shared constants address that finding; fresh independent re-review required.
- Merge/ancestry evidence: feature started at fetched beta `a9d625d`; merged current beta `b095679` at `36de6a151f226c909079cb9058fb1b88492b04a6` before this remediation. Re-fetch before merge.

## Blockers and deferred work

- **Missing test or evidence:** live Hoster admission and proxy readiness on a new owned task; not needed to merge source, required to call the capacity issue operationally relieved. Recheck listeners and leases first; run only an owned task through normal provisioning when available.
- **Missing durable repair:** old ownerless rows cannot be released from age or inactive browser status. Wire supervisor-issued terminal receipt after direct replay, and fence exact run before reaping; separately verify owner lifecycle. This change does not retroactively prove terminality.
- **Existing/legacy leases:** the new source refuses *new* Proxy Store leases on overflow ports and skips active legacy ones, but does not invalidate them or control an older checkout. Before Hoster activation, recheck all five candidate ports for listeners and active leases and defer activation if ownership is ambiguous. A directly invoked unmanaged proxy outside Proxy Store still relies on the OS bind conflict and readiness checks, not a global reservation.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/task-mitm-overflow-capacity-20261006`
- **Latest immutable recovery checkpoint:** `086ee51e32a834a21e286ccf302557c9452098f9`
- **Feature implementation commit(s):** `5c24dfee67fc6171d02b74ae66e2a664111ce818`, `086ee51e32a834a21e286ccf302557c9452098f9`
- **Exact resume point:** get fresh independent release review of the reconciled feature tip and old-lease activation boundary; if accepted, integrate through beta.
- **Working-tree state at handoff:** clean after dossier-only checkpoint update.

## Decision gates

- **Integration gate:** independent review of the exact diff/dossier and focused regression; current fetched beta ancestry.
- **Activation / cohort gate:** check selected Hoster runtime and candidate ports/lease stores anew; confirm no shared in-progress task is interrupted. No service stop/restart or old-row cleanup.
- **Promotion gate:** separate main-lane decision and runtime receipt; not implied by beta merge.

## Decision record

- 2026-10-06 — created a bounded bridge for exhausted task-MITM capacity; no old reservation was changed.
- 2026-10-06 — independent first review blocked beta on custom standalone lease collision; reconciled to beta `b095679` and added a shared reserved overflow bound with Proxy Store acquisition guard and RED/GREEN coverage. Re-review pending.
