# Error Store installed-dependency test repair

## Intent

Make the Error Store CLI regression tests run against BBH's pinned installed
Bounty Core dependency by default, while preserving `BOUNTY_CORE_TEST_SOURCE` as
an explicit isolated-source override.

## Branch and target

- Feature branch: `fix/error-store-test-install`
- Base: BBH `beta` at `6dea5c2f568a2eb1c10e8b5209e191d265382326`
- Intended integration target: `beta`

## Implemented contract

The subprocess test helper inherits a specific test Core source only when
`BOUNTY_CORE_TEST_SOURCE` is set. Otherwise it removes inherited `PYTHONPATH`
so the subprocess resolves the pinned installed Bounty Core package, matching a
normal BBH runtime.

## Evidence

- RED: an isolated temporary venv with `requirements-bounty-core.txt` installed
  failed because the helper required `BOUNTY_CORE_TEST_SOURCE` despite the pinned
  package being available.
- GREEN: after this repair, the same isolated venv ran `agents/test_error_store.py`
  with `2 passed`, plus `agents/test_hypothesis_ledger.py` and
  `agents/test_map_store.py` with `76 passed`.

## Activation decision

Independent review accepted `b1528954c66ff1f489eb6d5a628cdce877664172`.
It verified both installed-pin resolution under a hostile inherited `PYTHONPATH`
and explicit-source isolation; neighboring tests passed (`76 passed`). This
repair is approved for BBH `beta` integration.

## Resume point

Merge this clean reviewed repair into BBH `beta`, re-run its isolated temporary-
venv tests, push beta, then remove this merged dossier/worktree/feature branch.