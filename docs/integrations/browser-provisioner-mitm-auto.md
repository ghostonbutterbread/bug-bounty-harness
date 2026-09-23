# Browser provisioner task MITM integration dossier

- **Status:** feature, runtime activation blocked
- **Owner:** Hermes bugfix subagent
- **Branch / worktree:** `feat/browser-provisioner-mitm-auto-v2` / `/home/ryushe/worktrees/bbh-browser-provisioner-mitm-auto-v2`
- **Base commit:** `af9dae9` (fetched `origin/beta`)
- **Intended target:** `beta`; no merge or push authorized for this handoff
- **Last updated:** 2026-09-23
- **Latest immutable recovery checkpoint:** pending commit
- **Implementation commit:** pending commit
- **Inspiration:** older feature branch `feat/browser-provisioner-mitm-auto`, commits `7e28a7a`, `d2b28a3`; reference only, not transplanted wholesale.

## Intent and implemented contract

Preserve current beta's multi-instance account selection, lease/admission ordering, idle reclaim, owner hold, control fencing and watcher while provisioning a private task/run MITM listener before browser dispatch. Default `--proxy mitm` requires its CA and `import` trust; `--proxy external` uses explicit routing; `--proxy none` forces `--no-proxy-server` despite ambient routes. Running browser reuse requires matching route and trust. Startup intent is recorded before dispatch under the node lock shared with finish. Browser release does not finish the task proxy so direct replay remains possible. `task-proxy-status` and `task-proxy-finish` expose state and close/index private flows; finish rejects active or starting browser, retains reservation on stop, CA, or indexing failure, removes only matching CA trust in stopped profiles, and skips a nickname replaced by another task's CA. No shared Caido fallback.

## Evidence and review

- Regression: `python -m pytest -q agents/test_browser_provisioner.py agents/test_chromium_test_launcher.py agents/test_browser_selection.py agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_startup_diagnostics.py --basetemp=/home/ryushe/.hermes/profiles/bugfix/cache/scratch/s4` — **188 passed**. The short physical scratch basename avoids the existing Unix socket fixture's `AF_UNIX path too long` failure under pytest's default nested scratch prefix.
- Independent review: pending parent/reviewer.
- Merge/ancestry: branch based on `af9dae9` beta; no merge performed.

## Blockers and deferred work

- **Missing evidence:** current v2 real browser-origin HTTPS flow through its leased proxy, and browser root plus renderer cgroups with effective memory bounds. Earlier old-feature Chrome smoke showed root escaping bounded launcher unit into an unbounded `app-com.google.Chrome` sibling scope, browser loopback bypassing MITM; a separately explicit proxied fixture indexed while 21 Google background flows appeared. That does not prove v2 runtime behavior. Current beta lifecycle preserves pipe-fenced managed control but does not itself prove Chrome cgroup containment. Do not claim runtime activation or send a live worker until this is verified.
- **Command / fixture:** isolated `about:blank` request through provisioner on browser node with task MITM, CDP-navigate to approved loopback HTTPS fixture, inspect owned flow and `/proc/<root-pid>/cgroup`, `/proc/<renderer-pid>/cgroup`, effective `MemoryHigh`/`MemoryMax`, exact unit, and stop/release/finish receipts. Trigger on available disposable host fixture and reviewer approval. A queued admission result is not a startup smoke.
- **Missing review:** independent diff review plus full relevant integration suite before merge. Trigger after feature commit.

## Interruption / resume handoff

- **Branch/ref:** `feat/browser-provisioner-mitm-auto-v2`
- **Checkpoint / implementation commits:** pending commit
- **Exact resume point:** run broader regression suite, inspect diff and runtime fixture; parent to review/integrate only after required gates.
- **Working tree:** pending final commit.

## Decision gates

- **Integration:** tests and independent review, no unresolved beta lifecycle regression.
- **Activation:** actual browser cgroup and browser-origin proxied HTTPS flow proven on intended node.
- **Promotion:** separate stable review, not implied by this feature.

## Decision record

- 2026-09-23 — forward-port on current beta lifecycle rather than copy obsolete provisioner; runtime activation held pending current-node evidence.
