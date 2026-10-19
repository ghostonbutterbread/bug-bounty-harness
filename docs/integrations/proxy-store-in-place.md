# Proxy-store in-place integration dossier

- **Status:** review-ready (local commit only; integration and activation deferred)
- **Owner:** Hermes bugfix agent
- **Branch / owning ref:** `fix/proxy-store-in-place-20261019`
- **Worktree:** `/home/ryushe/projects/_wt/bbh-proxy-store-in-place-20261019`
- **Base commit:** `2c61677e3b869e90b0a64b4268bff8cf60c0a458` (`origin/beta` fetched)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Latest immutable recovery checkpoint:** `fa0d28d` (branch tip)
- **Feature implementation commits:** `140d4d5`, `fa0d28d`
- **Inspiration:** correct beta's relocation/gate from `2eabda9` and `56c3117` to keep one existing DB.

## Intent and implemented contract

Keep `~/.local/share/ghost/proxy-store/proxy_store.sqlite` as the sole default for proxy-store and standalone `mitm_lane index-store`; task-proxy finish/recover uses proxy-store's default. A real owner-controlled directory with 0700 mode reuses the existing DB and active reservations; no data migration, second DB, backup unlink, automatic live chmod, or writer freeze is performed. Existing group/world-writable final directories (Hoster: 02770) fail before SQLite open and retain their mode. Directory symlinks and untrusted path components remain rejected. Existing 0755 owner-controlled default parent can still be tightened to 0700 by the opener as before; group-writable parents are rejected first.

## Evidence and review

- Focused fixture: 02770 real directory with populated request + live lease is rejected unchanged, then fixture-only chmod 0700 preserves inode, request, and port reservation; populated artifact-mount symlink and dangling symlink fail. Standalone index default and task-proxy completion paths covered.
- Tests: `/home/ryushe/projects/bug_bounty_harness-runtime-beta-coverage-20261016/.venv/bin/python -m pytest agents/test_proxy_store.py agents/test_proxy_store_default_path.py agents/test_browser_provisioner.py agents/test_hoster_mitm_lane.py -q --basetemp=/home/ryushe/.cache/pytest-proxy-in-place-20261019` → **85 passed**. The initial `/tmp`-based run failed because the secure opener correctly rejects world-writable `/tmp` ancestors; using a private Hoster cache basetemp resolved environmental failures. A test fixture also needed `sqlite3.Row` and explicit chmod under umask; both corrected.
- Read-only live preflight: `~/.local/share/ghost/proxy-store` is a real UID 1000 directory mode 2770; its existing DB is UID 1000 mode 0600. `.local`, `share`, `ghost` are real UID 1000 directories mode 0755, and home is 0750. Alternate-name `proxy-store.symlink-backup` remains a symlink. State-path DB directory does not exist. No live DB open or mode change was performed.
- Reference-impact audit: bounded `git grep` finds only updated runtime defaults and tests; state-path references in tests assert its absence. README preflight describes exact operator action.
- Independent review: pending parent review. No merge/push/activation.
- Source branch: `beta`; descendants: no branch propagation requested. Existing feature history is superseded in beta by this correction, not rewritten.

## Blockers and deferred work

- **Live activation:** requires an operator to confirm no other UID/group consumer needs access and perform `chmod 0700 "$HOME/.local/share/ghost/proxy-store"` on Hoster's actual real directory, then verify mode, DB inode, requests, and active leases. The permission-only metadata change does not require a same-UID SQLite writer freeze or WAL copy, but removing group access may affect group-based consumers. No live chmod, service stop, or source activation authorized for this branch.
- **Integration:** independent review and reconciliation with current `origin/beta` before any beta merge; no merge or push authorized here.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/proxy-store-in-place-20261019`
- **Latest immutable recovery checkpoint:** `fa0d28d` (reachable from this branch)
- **Feature implementation commits:** `140d4d5`, `fa0d28d`
- **Exact resume point:** review focused diff, confirm beta tip and tests, then obtain operator decision on integration and separate live chmod.
- **Working-tree state at handoff:** expected clean after scoped commit.

## Decision gates

- **Integration gate:** parent independent review, fetch current beta, test reconciled tree.
- **Activation gate:** authorized mode change and runtime checkout selection separately; no migration.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-19 — corrected relocation into in-place path with private-parent preflight; local verification passed; no external state changed.
