# Browser/proxy orphan lifecycle integration dossier

- **Status:** blocked
- **Owner:** Hermes bugfix
- **Branch:** `fix/papercut-orphan-lifecycle`
- **Base commit:** `6a72fb5` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-27
- **Owning feature branch/ref:** `fix/papercut-orphan-lifecycle`
- **Latest immutable recovery checkpoint:** `3e93b7995a5a7d37b4bc2ce4390b5bd7a76fa01e`
- **Feature implementation commit(s):** `3e93b7995a5a7d37b4bc2ce4390b5bd7a76fa01e`
- **Inspiration / canonical references:** PC-20260927-194446-2f4b6822; Discord thread 1564696750067949650

## Intent

The legacy `reap-idle` output reported no stops while stale browser leases and task-MITM units remained. Do not turn elapsed time or deleted task directories into task-terminal proof: replay may outlive the browser, and old rows have no durable owner identity. Guard automatic retirement against canonical lease mismatch and make eligibility failures visible without exposing task names or traffic.

## Implemented contract

- `maintain` checks exact active canonical lease ownership before automatic retirement on both terminal and already-stopped paths; mismatch is retained with a lifecycle error.
- `reap-idle` emits bounded reason counts for running browsers and aged task proxies it cannot reclaim, including failed freeze/stop and failed proxy finish. Eligible tasks retain existing terminal-owner, idle/quiet flow, no-client, canonical owner, and stop-verification gates.
- No age-only cleanup, live Hoster service stop, or retroactive ownership assignment. Old ownerless rows remain for manager-authoritative task reconciliation.

## Evidence and review

- `python3 -m pytest -q agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_provisioner.py -k 'not task_proxy_completion_indexes_private_default_and_releases'`: 139 passed, 2 deselected after diagnostic changes; `git diff --check` passed.
- Broad two-module run: 64 passed, 2 failed before exercising cleanup due installed mitmproxy `Client` constructor incompatibility in real-flow fixture. Existing papercut tracks that unrelated test environment mismatch.
- Independent review: do not integrate as a fix for the papercut. The patch does not reclaim ownerless records; canonical-owner check is not atomic with stop across the manager and lease databases. Reviewer ran three modules: 138 passed, 2 deselected before the post-review diagnostic changes.
- Hoster read-only inventory: current ownerless running rows and stale proxy reservations; no live cleanup attempted. Tmux sidecar inspected three registered scopes, stopped none.

## Blockers and deferred work

- **Missing test or evidence:** verify exact terminal ownership and replay quiescence for legacy Hoster rows before release/finish; unavailable owner fields cannot be inferred from age or absent lane state.
- **Command / fixture / environment needed:** manager-owned task inventory, exact lease/unit/flow proof, and task-owner confirmation; do not use mass-stop.
- **Trigger to run it:** when an owner or operator confirms the affected task terminal and the exact service/browser identity is reconciled.
- **Why it blocks integration, activation, or promotion:** the incomplete ownership fence and missing task-terminal proof block integration as a papercut fix; no runtime activation or closure is justified.
- **Next completion step / successor reference:** read back each exact Hoster row, reconcile owner state, then use exact browser release and task-proxy-finish/recover with verified stop and indexing.
- **Safety gap before integration:** a canonical lease may change after the new read-only check but before `retire` stops the unit. Lock/fence both ownership records through stop/release and fault-inject this race; otherwise retain this branch as an incomplete diagnostic/safety proposal, not a shipped cleanup fix.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-orphan-lifecycle`
- **Latest immutable recovery checkpoint:** `3e93b7995a5a7d37b4bc2ce4390b5bd7a76fa01e`
- **Feature implementation commit(s):** `3e93b7995a5a7d37b4bc2ce4390b5bd7a76fa01e`
- **Exact resume point:** add cross-store owner fence and proof of task terminality for legacy ownerless rows; rerun complete focused suite, independent re-review, then integrate if accepted. Do not close papercut on diagnostic output alone.
- **Working-tree state at handoff:** clean after dossier-only checkpoint; feature remains blocked, not merged.

## Decision gates

- **Integration gate:** blocked on reviewer cross-store ownership race and missing solution for ownerless task termination; focused tests, independent re-review, exact beta divergence and clean integration checkout.
- **Activation / cohort gate:** separate Hoster runtime verification; source publication is not activation.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-27 — current beta still has ownerless legacy rows. Chose to report blocked eligibility and fence automatic retirement rather than unsafe age-only reclamation.
- 2026-10-27 — independent review rejected integration as a complete fix; expanded refusal diagnostics but retained the cross-store race and legacy owner-evidence gap as blockers.
