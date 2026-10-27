# Browser stop/release cross-store fence

- Status: local checkpoint; no integration or runtime activation.
- Owner branch/worktree: `fix/papercut-stop-fence-child` at `/home/ryushe/worktrees/bbh-papercut-stop-fence-child`.
- Base: `9237cbf` on `fix/papercut-orphan-lifecycle`; intended merge-back target is that parent feature branch, then its planned `beta` integration after independent review.
- Inspiration: PC-20260927-194446-2f4b6822 and parent `docs/integrations/orphan-lifecycle.md` reviewer safety gap.

## Contract and evidence

The manager's node lock and canonical `BEGIN IMMEDIATE` span exact manager/canonical identity and reservation reread, unit/root/CDP stop proof, canonical release in the same connection, stop receipt, and manager terminal state. Explicit release and automatic retire share this boundary. A failed `is-active` query is not terminal proof: `stopped()` requires an affirmative `ActiveState` readback plus terminal root and unavailable CDP. Direct CLI release of a managed registered browser is refused even with a matching `manager_id`; pre-launch cleanup remains available. A stop interrupted before its receipt can recover an unloaded unit without `InvocationID` only with exact canonical/manager identity, no observed replacement invocation, and independent unit/root/CDP terminal proof. A canonical release committed before manager terminal state can be reconciled on retry only for the exact released owner with retained stop proof and terminal evidence. No age-only or ownerless reclaim is added; task proxy finish remains separate.

Tests use disposable stores and systemd/CDP mocks; the canonical-writer race proves the write lock spans stop/release, not the manager writer. The original 10 stop-fence tests and new failure, bypass, interrupted-stop and negative-proof regressions are included; adjacent test fixtures that used direct managed release now model manager-owned release. Final focused receipt: `python3 -m pytest -q agents/test_browser_stop_fence.py agents/test_browser_lease_recovery.py agents/test_browser_resources.py agents/test_browser_provisioner.py agents/test_browser_selection.py agents/test_browser_auth_fence.py agents/test_browser_safe_resume.py agents/test_browser_profile_lease.py agents/test_browser_stopped_reservation.py -k 'not task_proxy_completion_indexes_private_default_and_releases'` → 283 passed, 2 deselected, 41 subtests passed. The deselected task-proxy real-flow fixture is an existing incompatibility, not a stop-fence pass. `git diff --check` and staged diff inspection precede the local commit.

## Deferred gates and resume

Independent fresh review and full focused rerun on the final checkpoint are required before parent integration. The existing task-proxy real-flow fixture incompatibility and legacy ownerless Hoster task-terminal evidence remain parent blockers. Do not mutate Hoster or conclude the original papercut is closed. Resume by reviewing the exact child diff and tests, then deciding merge-back into the parent feature branch; no push, merge, or activation was authorized in this handoff.
