# Auth-seed permissions integration dossier

- **Status:** feature (not integrated)
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/auth-seed-permissions-20261019`
- **Worktree:** `/home/ryushe/projects/_wt/bbh-auth-seed-permissions-20261019`
- **Base commit:** `9f56eb16d480eda212f7f76108a329d434aa9d9a` (`origin/beta`, fetched)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Latest immutable recovery checkpoint:** this branch's implementation commit (see Git history)
- **Inspiration:** `PC-20261019-181155-594829ea`, reported 0664 auth seed blocking named-account browser provision

## Intent and implementation

The BBH account-management `auth_resolver.write_auth_seed` is the indexed seed writer for proxy-refresh; `chromium_test.load_auth_seed` validates seeds before browser launch, reached by the provisioner. Establish 0600 on the temporary file descriptor before writing JSON and atomically replace only an existing owned regular owner-only seed. Refuse existing loose, foreign-owned or symlink destinations without changing their contents or mode. The launcher retains its strict permission rejection and explains operator inspection and manual repair. No live credentials, browser profiles, or state were modified. The reported manually created seed may have been written outside this indexed BBH writer; this patch does not claim to repair that external creation route.

## Evidence and review

- `GHOST_AGENT_RUNTIME=local PYTHONPATH=skills/account-management/scripts:skills/chromium-test/scripts /home/ryushe/projects/bug_bounty_harness-runtime-beta-coverage-20261016/.venv/bin/python -m pytest agents/test_auth_resolver.py agents/test_chromium_test_launcher.py -q`: 71 passed.
- Initial full run under SSH with runtime `hoster`: 68 passed, three unrelated launcher tests refused the SSH cgroup; fixture runtime override above passed all.
- Focused regressions check mode during JSON write under permissive umask, insecure-file nonmutation, symlink refusal, and actionable launcher error with unchanged mode.
- Independent review/integration/push: not requested; feature branch remains isolated.

## Blockers and deferred work

- The exact out-of-repository manual seed creator used by the Pi report was not identified from BBH's indexed writer. If it is a separate maintained tool, inspect its owner before integrating as a universal creation fix.
- No live named-account replay was run (requires real credentials/state; not authorized). Run an owner-approved isolated fixture or live check only upon explicit authorization.

## Interruption / resume handoff

- **Owning feature ref:** `fix/auth-seed-permissions-20261019`
- **Recovery checkpoint:** implementation commit on this branch; use `git rev-parse HEAD`.
- **Exact resume point:** review current diff and owner boundary; no merge/push.
- **Working-tree state at handoff:** clean after commit.

## Decision gates

- **Integration gate:** independent review and owner decision about external manual creation route.
- **Activation gate:** none performed; beta/runtime unchanged.
- **Promotion gate:** not requested.

## Decision record

- 2026-10-19 — scoped fix and regression verification on isolated feature branch.
