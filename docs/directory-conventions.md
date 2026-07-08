# Bug Bounty Harness Directory Conventions

Status: active
Owner: Ghost / Bug Bounty Harness maintainers
Last updated: 2026-06-26

This repo is being cleaned up incrementally. Prefer direct migrations when
in-repo callers can be updated safely: put new implementation code in
responsibility-owned packages, update internal imports to the canonical path,
and remove old wrappers once tests prove they are unused. Use temporary shims
only when an old public import or CLI path still has known consumers.

## Layout

- `agents/` remains the public compatibility namespace for harness modules and
  executable entrypoints.
- `agents/<responsibility>/` owns reusable implementation code grouped by
  durable responsibility, such as `base_team`, `hunt_pipeline`, `recon`,
  `dynamic_validation`, and `artifacts`.
- `agents/<legacy_name>.py` may remain temporarily as a compatibility shim when
  callers still use that import path or script path. Shims should import from the
  package owner and contain no business logic beyond script-path bootstrapping.
  Prefer deleting the shim in the same slice after updating in-repo callers.
- `tests/` is the preferred home for new or moved focused pytest tests.
  Existing `agents/test_*.py` files can move gradually when the touched slice is
  safe to isolate.
- `docs/` owns durable conventions, specs, and playbooks. Update docs when a
  migration establishes a pattern future agents should follow.
- `skills/` and `prompts/` are the source-of-truth skill wrappers and playbooks;
  do not move them during code structure cleanup unless the skill itself is the
  target of the change.

## Import Rules

- New internal imports should target the responsibility package, for example
  `from agents.artifacts.map import map_path`.
- Existing in-repo callers should be updated to the canonical package path
  during the same migration slice.
- Temporary compatibility shims should re-export the same public names and
  delegate CLI execution to the new module's `main()`. Remove the shim once
  `rg` and tests show no known consumers remain.
- Avoid adding new top-level `agents/*.py` implementation modules unless they
  are intentional public entrypoints or compatibility wrappers.

## Test Rules

For every migrated slice, add or update focused tests that cover:

- the new import path
- the old compatibility import path, only when a temporary shim remains
- CLI/help smoke for any moved executable module that remains public
- behavior that existed before the move

Run focused pytest for the touched tests, `py_compile` for touched Python
modules, and `git diff --check`. Do not use full bounty pipeline runs as routine
verification for directory cleanup.

## First Migration Pattern

The first representative slice moved the artifact-map helper from
`agents/bounty_artifact_map.py` to `agents/artifacts/map.py`. In-repo callers
were updated to the canonical path, and the old wrapper was removed after review
showed no remaining internal consumers. Future migrations should follow the
same direct-update pattern when possible; keep a shim only for known public
compatibility needs.
