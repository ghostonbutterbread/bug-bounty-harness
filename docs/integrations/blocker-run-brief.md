# General optional blocker checks and completion briefs

- **Objective:** let any agent check known external blockers before wasting effort, and show Ryushe only its run's remaining blockers at completion.
- **Branch:** `feat/blocker-run-brief`
- **Base / target:** `beta` at `77f02b6` → `beta`
- **Core dependency:** Bounty Core beta `1bba64b557aa3b604092b5bad47689fcb40cc0f7` (must merge first).
- **Implementation commit:** pending commit after the clean dependency smoke.

## Contract

`check` is optional and only for plausible external prerequisites. It returns a
known blocker and its unblock condition so an agent can stop rediscovering it.
Agents first perform ordinary authorized setup; they record a blocker only if
the needed action lies outside their authority. `brief --run-id` produces an
end-of-run summary of open blockers and `next_to_push` actions. It does not
force coverage checks or automatic retries.

## Evidence

- `PYTHONPATH=/home/ryushe/worktrees/bounty-core-blocker-run-brief BOUNTY_CORE_TEST_SOURCE=/home/ryushe/worktrees/bounty-core-blocker-run-brief python3 -m pytest -q agents/test_account_inventory.py agents/test_attempts.py agents/test_blockers.py agents/test_error_store.py` → 20 passed.

## Next action

Independent review, then merge Core first and BBH second into beta.