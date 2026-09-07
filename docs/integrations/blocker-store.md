# Prerequisite-aware Blocker Store integration

- **Task:** `t_46c5491e`
- **Branch:** `feat/blocker-store`
- **Base / target:** `beta` at `d9fed36` → `beta`
- **Dependency:** Bounty Core `feat/blocker-store` commit `ad4bc75222601ccf68bc424b9d65613cdcccd787` (immutable pin in `requirements-bounty-core.txt`).

## Contract

`bbh agents/blockers.py` adapts Bounty Core’s `BlockerStore`. Access-control guidance requires an open blocker when selected owned accounts lack a feature-specific capability, role, or object fixture. Such a condition invalidates a feature coverage claim; routing/method observations remain observations only.

Completion summaries query the exact subject/scope coverage gate. An open blocker requires `not demonstrated under available prerequisites`.

## Evidence

- `env -u PYTHONPATH -u BOUNTY_CORE_TEST_SOURCE python3 -m pytest -q agents/test_blockers.py` → 2 passed against the installed Core adapter.
- `PYTHONPATH=/home/ryushe/worktrees/bounty-core-blocker-store BOUNTY_CORE_TEST_SOURCE=/home/ryushe/worktrees/bounty-core-blocker-store python3 -m pytest -q agents/test_account_inventory.py agents/test_attempts.py agents/test_blockers.py agents/test_error_store.py` → 19 passed.

## Activation boundary

Core must merge and be available to the BBH runtime before this adapter/skill is activated. This branch has no live target effect.

## Next action

Independent review, focused regression suite after any repair, then Core-first/BBH-second beta integration.