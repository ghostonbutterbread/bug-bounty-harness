# HackerOne structured-scope pagination repair

- **Task:** prevent partial HackerOne structured-scope pulls from being treated as complete.
- **Branch / worktree:** `fix/hackerone-scope-pagination` at `/home/ryushe/worktrees/bbh-hackerone-scope-pagination`.
- **Base / target:** `origin/beta` `515c60886a857317178e56143da5eedbad030147` → `beta`.

## Repair

The initial structured-scope integration requested only the first 500 records. The GraphQL query now requests `pageInfo`, follows `endCursor` until `hasNextPage` is false, and joins every returned page before parsing. It refuses malformed/missing pagination metadata and non-progressing cursors rather than silently persisting a partial scope.

## Evidence

- Synthetic two-page regression verifies cursor propagation and combined edges.
- Regression verifies a scope response without pagination metadata fails closed.
- Regression verifies a repeated continuation cursor fails closed and asserts the outgoing GraphQL query retains its cursor and `pageInfo` contract.
- Focused suite: `PYTHONPATH="$PWD" python3 -m pytest agents/test_scope_puller_seed_files.py agents/test_scope_manager.py agents/test_scope_validator.py agents/test_scope_seed_files.py -q` — 14 passed.
- Compilation: `PYTHONPATH="$PWD" python3 -m py_compile agents/scope_puller.py program_config.py`.
- Diff check: `git diff --check`.
- Public, read-only `snapchat` smoke: 46 structured-scope edges, `hasNextPage=False`, 32 domains, 1 URL; no scope files written.

## Activation boundary

This branch is not merged or deployed. Before beta integration: commit, independent read-only review of the exact tip, then merge/test/push from the clean beta worktree. Hoster remains runtime-only and must fast-forward beta before its non-mutating smoke.
