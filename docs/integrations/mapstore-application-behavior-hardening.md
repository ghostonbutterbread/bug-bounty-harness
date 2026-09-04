# MapStore Application Behavior Regression Hardening

- **Status:** verified, awaiting beta integration
- **Owning feature branch/ref:** `fix/mapstore-application-behavior-regressions`
- **Base beta commit:** `d3cef5f38f3cab80488306a851644eeb67cf588d`
- **Intended integration target:** `beta`
- **Context:** Follow-up requested after merging Application Behavior records to beta.

## Change

Add regression coverage only—no runtime behavior changes:

1. A behavior write creates no URL-Ingest receipt beyond the cited normal MapStore observation.
2. Two separate CLI processes can concurrently write behavior records without losing either JSONL entry; concurrent normal observations can link an existing behavior ID.

## Evidence

Focused verification:

```text
PYTHONPATH=/home/ryushe/worktrees/bbh-mapstore-application-behavior-hardening \
  /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest \
  agents/test_map_store.py::TestMapStore::test_write_application_behavior_is_queryable_without_becoming_an_observation \
  agents/test_map_store.py::TestMapStore::test_concurrent_behavior_writes_and_observation_links_preserve_all_records -q
```

Expected result: 2 passed.

## Activation boundary

This is test-only hardening. It requires a separate reviewed merge into beta; it does not activate a runtime or change MapStore semantics.
