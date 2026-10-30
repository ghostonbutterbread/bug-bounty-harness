# Runtime IDNA manifest contract integration dossier

- **Status:** feature; independent review and integration pending
- **Owner / task:** t_2ed920a6, PC-20261030-025000-2d0e11c5
- **Branch:** `fix/runtime-idna-manifest-t2ed920a6`
- **Worktree:** `/home/ryushe/worktrees/bbh-runtime-idna-manifest-t2ed920a6`
- **Base:** fetched `origin/beta` at `28f0fd8644412951d6c719bf08ba28c27b16fd59`
- **Intended integration target:** `beta` (no integration authorized in this task)
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** `fix/runtime-idna-manifest-t2ed920a6`
- **Latest immutable recovery checkpoint:** `28c0724a1e1651dca74f8dcacd52affe99be41e2`
- **Feature implementation commit(s):** `28c0724a1e1651dca74f8dcacd52affe99be41e2`
- **Inspiration / references:** manifest addition in `878bcd028caccffb774a116c589f0bf2bd441c88`; `tests/test_runtime_dependencies.py`; `agents/scope_validator.py` and `agents/subdomain_agent.py`.

## Intent and implemented contract

The beta-owned test's exact expected manifest omitted IDNA after the scope-guard addition. It now requires the literal `idna>=3,<4` once, alongside the unchanged exact multiset of every other dependency, single-manifest check, and superseded Core pin check. Synthetic copies exercise current, missing IDNA, wrong range, duplicate IDNA, and changed httpx. No manifest, installation, application behavior, or sibling report-pin branch changes.

`setup.sh --install-python-deps` uses root `requirements.txt` via uv. Scope validator imports third-party `idna` directly and calls `idna.decode(..., uts46=True, std3_rules=True)`; subdomain agent uses `idna.encode` similarly. The only tracked Python manifest/lock found is `requirements.txt`; installed httpx requires idna, requests accepts `idna>=2.5,<4`, but neither transitively guarantees our required minimum 3. An explicit direct requirement is justified, not a relaxed set or new manifest.

## Evidence and review

- RED under inherited kernel seccomp denial: original `tests/test_runtime_dependencies.py` yielded 1 failed, 1 passed, unexpected `idna>=3,<4`. The new synthetic regression before fixing the expected list failed for the current manifest and missing-IDNA variant; wrong-range was rejected.
- GREEN: `tests/test_runtime_dependencies.py agents/test_scope_validator.py agents/test_scope_path_normalization.py tests/test_scope_host_normalization.py tests/test_scope_import_safety.py tests/test_subdomain_provider_validation.py`: **395 passed, 15 subtests passed**. `git diff --check` passed. Network denial was verified with a socket call returning EPERM. No target or data access intended.
- Command: from this worktree, set `HOME=$TMPDIR/bbh-idna-test-home`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONDONTWRITEBYTECODE=1`; run `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python $TMPDIR/bbh-idna-offline-exec.py /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m pytest -p no:cacheprovider --basetemp=$TMPDIR/bbh-idna-final` followed by the above test paths. The task-owned scratch launcher applies libseccomp EPERM rules to socket, connect, sendto, sendmsg and sendmmsg before exec; children inherit the filter. Scratch may expire; recreate equivalent guard if absent. `unshare -n` was unavailable (EPERM).
- Environment: Python 3.11.15, pytest 9.1.1, idna 3.18. Core metadata specifies `6c36ee88a60073e1b687ec32deeade24ffafdd4f`; editable import points to a scratch copy, and all 18 tracked `bounty_core` files compared byte-for-byte to that Git commit. Validator imported from this feature checkout. No dependency install was performed.
- Independent review: **pending**. Feature is not merged, pushed, activated, or closed. Another agent owns the separate finding-report pin worktree.
- Branch ownership: introduced in beta with scope guard, so beta is the repair target; propagation to any affected descendants is an integration owner's follow-up, not performed here.

## Blockers and deferred work

- Independent review must examine committed diff, the exact expected-set preservation and synthetic cases, and rerun the offline suite. Trigger: parent receives this feature branch. Missing independent evidence blocks beta integration.
- Fetch `origin/beta` again, compare ancestry and reconcile only in this feature if needed, then review the actual candidate. Integration and post-merge verification are explicitly deferred to parent, and must not write into the separate report-pin worktree. Activation/stable promotion and task closure are outside this task.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/runtime-idna-manifest-t2ed920a6`
- **Latest immutable recovery checkpoint:** `28c0724a1e1651dca74f8dcacd52affe99be41e2`; verify subsequent dossier-only commit and branch tip
- **Feature implementation commit(s):** `28c0724a1e1651dca74f8dcacd52affe99be41e2`
- **Exact resume point:** independent review and beta freshness check; integrate only with separate authorization.
- **Working-tree state at handoff:** committed feature; verify tip and status.

## Decision gates

- **Integration:** independent review, current beta reconciliation, scoped tests.
- **Activation / promotion:** not authorized or claimed.
- **Decision record:** 2026-10-29 — implement narrowly, hand off for review.
