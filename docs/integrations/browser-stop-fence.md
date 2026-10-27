# Browser stop/release cross-store fence

- Status: local checkpoint; no integration or runtime activation.
- Owner branch/worktree: `fix/papercut-stop-fence-child` at `/home/ryushe/worktrees/bbh-papercut-stop-fence-child`.
- Base: `9237cbf` on `fix/papercut-orphan-lifecycle`; intended merge-back target is that parent feature branch, then its planned `beta` integration after independent review.
- Inspiration: PC-20260927-194446-2f4b6822 and parent `docs/integrations/orphan-lifecycle.md` reviewer safety gap.

## Contract and evidence

The manager's node lock and canonical `BEGIN IMMEDIATE` span exact manager/canonical identity and reservation reread, unit/root/CDP stop proof, canonical release in the same connection, stop receipt, and manager terminal state. Explicit release and automatic retire share this boundary. A canonical release committed before manager terminal state can be reconciled on retry only for the exact released owner with retained stop proof and independently terminal root/CDP/unit evidence. No age-only or ownerless reclaim is added; task proxy finish remains separate.

Focused temporary-store race/failure tests: `python3 -m pytest -q agents/test_browser_stop_fence.py` (10 passed); existing focused suite `python3 -m pytest -q agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_provisioner.py -k 'not task_proxy_completion_indexes_private_default_and_releases'` (139 passed, 2 deselected before the final recovery-only refinement). `git diff --check` passed.

## Deferred gates and resume

Independent fresh review and full focused rerun on the final checkpoint are required before parent integration. The existing task-proxy real-flow fixture incompatibility and legacy ownerless Hoster task-terminal evidence remain parent blockers. Do not mutate Hoster or conclude the original papercut is closed. Resume by reviewing the exact child diff and tests, then deciding merge-back into the parent feature branch; no push, merge, or activation was authorized in this handoff.
