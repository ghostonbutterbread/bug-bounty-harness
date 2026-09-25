# Browser launcher startup diagnostics integration dossier

- **Status:** feature (checkpoint; independent integration review pending)
- **Owner:** Hermes bugfix task
- **Branch / owning feature ref:** `fix/browser-launcher-startup-diagnostics`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-launcher-startup-diagnostics`
- **Base commit:** `3e5d2eb1b46c9989dee99c5dbc7c84e95bd092f6` (`origin/beta`, fetched 2026-09-24)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-24
- **Latest immutable recovery checkpoint:** `e836e9ca07e993763c58e0b320ac2b9b7cd69e6d`
- **Feature implementation commit(s):** `e836e9ca07e993763c58e0b320ac2b9b7cd69e6d`
- **Inspiration / canonical references:** diagnostic descendant `fix/browser-preparation-diagnostics` commit `3f75875`; its fixture-auth code and dossier are deliberately excluded.

## Intent

At the beta-owned Chromium launcher boundary, a failed pipe-adapter import must be distinguishable from Chrome spawn failure without recording exception text, module names, paths, or secrets. Fixture evidence should retain only a validated exact browser unit identity. No auth fixture transaction or manager behavior change.

## Implemented contract

- The control-socket path records `adapter-import` begin/ready/failed around the `browser_control.PipeBrowser` import. ImportError (including ModuleNotFoundError) projects as `dependency`; existing spawn and other failure categories remain distinct. Exception propagation is unchanged.
- The disposable startup metadata projector accepts the new closed phase/category and retains `browser-<canonical-UUID>.service` only when the directory is a canonical UUID. Non-UUID directory names are omitted entirely. No raw traceback or stderr content is retained.
- Focused tests inject a secret-bearing import exception before spawn and exercise UUID-only projection and retained failure evidence.

## Evidence and review

- Isolated scratch venv installed directly from this worktree's root `requirements.txt` (including `bounty-core` pinned at `7b08495f65a50f733fc18213c38cc3ae8e91bdf5`, `aiohttp==3.14.3`, `pytest==9.1.1`); no shared beta `.venv` changed.
- `python -m pytest agents/test_browser_startup_diagnostics.py agents/test_chromium_test_launcher.py -q` with scratch-root `/proc/<pid>/fd/<fd>/pt` pytest basetemp: **59 passed**. Initial plain invocation: 58 passed, 1 failed solely because scratch-root pytest `control.sock` path exceeded Linux AF_UNIX limit; rerun with short alias passed without changing production code.
- `python -m pytest agents/test_browser_provisioner.py agents/test_browser_lifecycle_systemd.py -q -k 'not real_systemd and not live and not smoke'` with same basetemp: **36 passed, 2 skipped, 4 deselected**.
- `git diff --check`: clean. The separate systemd/real-browser path was not exercised; no browser units or Hoster resources touched.
- **Independent review:** code and focused tests approved; integration blocked pending this handoff correction. Reviewer independently observed 59 diagnostics/launcher passes and 36 provisioner/lifecycle passes (2 skipped, 4 deselected); real systemd startup untested.
- **Ancestry:** fetched `origin/beta` base above. The fixture transaction branch does **not** contain `3f75875`; that commit belongs to the separate `fix/browser-preparation-diagnostics` descendant. After beta integration, merge beta into each affected auth branch deliberately, retaining fixture-specific work and resolving equivalent diagnostic hunks without duplicate behavior. No rebase of shared descendants.

## Blockers and deferred work

- **Missing evidence:** integrated beta focused tests and real systemd startup receipt; the independent source review approved code subject to the corrected ancestry record above.
- **Command / environment:** review this branch diff against `origin/beta`; after authorized merge rerun the two commands above from the selected clean beta integration worktree with a synchronized isolated environment. A real systemd startup exercise requires an authorized disposable browser environment and is not claimed here.
- **Trigger:** parent approves and integrates into beta, then propagates to fixture descendant.
- **Why:** no integration or descendant propagation was authorized to this subtask.
- **Next completion step:** parent reviews feature commit, merges into beta if accepted, then merges beta into `feat/browser-auth-fixture-transaction` and reruns focused checks; retire this dossier from beta during integration.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-launcher-startup-diagnostics`
- **Latest immutable recovery checkpoint:** `e836e9ca07e993763c58e0b320ac2b9b7cd69e6d`
- **Feature implementation commit(s):** `e836e9ca07e993763c58e0b320ac2b9b7cd69e6d`
- **Exact resume point:** independently review the committed isolated fix, then integrate into beta only with separate authorization.
- **Working-tree state at handoff:** clean after dossier-only handoff commit

## Decision gates

- **Integration gate:** independent review, current beta reconciliation, clean target, focused post-merge tests; remove temporary dossier from target.
- **Activation / cohort gate:** none claimed; installed beta environment and real service remain unmodified.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-24 — scoped beta-owned generic launcher and sanitized evidence repair; fixture-auth transaction intentionally excluded.
