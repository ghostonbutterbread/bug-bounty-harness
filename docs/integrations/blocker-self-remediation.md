# Remediation-first blocker semantics

- **Objective:** prevent a known external blocker from short-circuiting ordinary authorized work an agent can perform itself.
- **Implementation commit:** `1055f7a78087254e1294f68c15ea762489878348`
- **Branch:** `fix/blocker-self-remediation`
- **Base / target:** `beta` at `ef2d445607c201a195b128744939fddd2f73d16e` → `beta`

## Contract

Before recording or honoring a blocker, an agent must attempt feasible ordinary
remediation: permitted signup/free trial, owned account/fixture creation, normal
feature setup, and bounded auth recovery. A known blocker is never permission
to stop a runnable task. Only the remaining external action is handoff-worthy.

The `check` response repeats this rule in machine-readable output so callers do
not interpret a known blocker as a terminal result.

## Evidence

- `PYTHONPATH=/home/ryushe/projects/bounty-core python3 -m pytest -q agents/test_account_inventory.py agents/test_attempts.py agents/test_blockers.py agents/test_error_store.py` → **23 passed**.
- Clean virtualenv installed `requirements-bounty-core.txt`, successfully recorded and checked a human-only external blocker with persisted remediation evidence, and rejected an open record without `--remediation-evidence`.

## Activation boundary

Beta integration does not activate/sync this behavior to a live runtime.