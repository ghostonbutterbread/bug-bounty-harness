# Browser provisioner task MITM integration dossier

- **Status:** per-browser D-Bus containment and interrupted-start reconciliation verified; headed/manual activation and independent review deferred
- **Owner:** Hermes bugfix subagent
- **Branch / worktree:** `feat/browser-provisioner-mitm-auto-v2` / `/home/ryushe/worktrees/bbh-browser-provisioner-mitm-auto-v2`
- **Base commit:** `af9dae9` (fetched `origin/beta`)
- **Intended target:** `beta`; no merge or push authorized for this handoff
- **Last updated:** 2026-09-23
- **Latest immutable recovery checkpoint:** `59a525e` (per-browser D-Bus repair; orphan-start repair follows in the next commit)
- **Implementation commits:** `421742ab90972ab7f454aa993941004dfbe4af17`, `d72d9675d2c8935a1a7081c7b32a8b7ba2110939`, `59a525e`; orphan-start repair in this handoff's next commit
- **Inspiration:** older feature branch `feat/browser-provisioner-mitm-auto`, commits `7e28a7a`, `d2b28a3`; reference only, not transplanted wholesale.

## Intent and implemented contract

Preserve current beta's multi-instance account selection, lease/admission ordering, idle reclaim, owner hold, control fencing and watcher while provisioning a private task/run MITM listener before browser dispatch. Default `--proxy mitm` requires its CA and `import` trust; `--proxy external` uses explicit routing; `--proxy none` forces `--no-proxy-server` despite ambient routes. Running browser reuse requires matching route and trust. Startup intent is recorded before dispatch under the node lock shared with finish. Browser release does not finish the task proxy so direct replay remains possible. `task-proxy-status` and `task-proxy-finish` expose state and close/index private flows; finish rejects active or starting browser, retains reservation on stop, CA, or indexing failure, removes only matching CA trust in stopped profiles, and skips a nickname replaced by another task's CA. No shared Caido fallback.

## Evidence and review

- Regression: `python -m pytest -q agents/test_browser_provisioner.py agents/test_chromium_test_launcher.py agents/test_browser_selection.py agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_startup_diagnostics.py --basetemp=/home/ryushe/.hermes/profiles/bugfix/cache/scratch/s4` — **188 passed**. The short physical scratch basename avoids the existing Unix socket fixture's `AF_UNIX path too long` failure under pytest's default nested scratch prefix.
- Per-browser-service containment repair: `systemd-run --user --setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent` is applied only to the Chrome-containing browser unit. The provisioner's `sysenv()` continues using the real `/run/user/<uid>/bus`; task MITM and watcher service dispatch are unchanged. Manual/KasmVNC flags and fallback remain forwarded unmodified. Regression asserts the browser override, real control-plane address, absent proxy override, and manual/KasmVNC forwarding.
- Focused suite (split because an all-in-one run exceeded the command timeout under host load): **193 passed** = 27 `test_browser_provisioner.py` + 65 `test_chromium_test_launcher.py`/`test_browser_selection.py` + 101 `test_browser_resources.py`/`test_browser_lease_recovery.py`/`test_browser_startup_diagnostics.py`. All used isolated `--basetemp` in profile scratch; `HARNESS_BOUNTY_ARTIFACT_ROOT` unset for the fixture that requires `/mnt/bounty`.
- Real v2 disposable headless Google Chrome 150 task-MITM smoke on this node: `start fixture anon1 --headless --display-backend default --proxy mitm --memory-high 384M --memory-max 512M` yielded `started`, live fenced CDP, and `proxy_cert_mode=import` / `proxy_cert_status.status=trusted` in both isolated NSS stores, without certificate-ignore. Chrome root PID 858473 and renderer PID 858548 both belonged to `browser-63cf822a-e185-4ba6-b701-6839f35da9fb.service`, with effective `memory.high=402653184`, `memory.max=536870912`. Browser CDP navigated to `https://10.0.0.11:<ephemeral>/dbus-fixture` (non-loopback local interface, not bypassed) and read `fixture-https-ok`. Task flow `task-d2fed8d1d1794c538db6a315af0b310a` contained `GET 10.0.0.11 /dbus-fixture 200`. Self-signed fixture upstream was trusted by the **disposable mitmdump wrapper only** (`ssl_verify_upstream_trusted_ca=<fixture.pem>`); production proxy configuration and source were not relaxed. The proxy remained ready after browser release; a direct proxied, CA-verified `GET /replay-after-release` returned 200 and was indexed. First finish stopped/indexed the listener, second finish returned `already_finished=true`. Browser unit inactive, root absent, CDP closed; state recorded zero active task proxies and zero running browsers. No target navigation or target requests were issued.
- Fixture teardown removed only the disposable state, profiles, flows, certificates, wrapper, server script and test scratch roots after exact fixture units and PIDs stopped; an unrelated active `browser-18d08d08-16bb-46f5-aa85-6afb9d629613.service` from another checkout was observed and left untouched.
- The initial self-signed-origin run returned proxy 502 with upstream certificate verification failure; it nevertheless confirmed cgroup containment and was released/finished. The fixture-only upstream CA trust resolved this without weakening browser NSS trust or the production task proxy.
- Independent review: pending parent/reviewer.
- Review repair: task reservation records owner process identity, unit invocation,
  and transition timestamp. Explicit recovery of interrupted `starting` or
  `cleanup-failed` requires stopped browser; a live unit additionally requires
  matching invocation, 7200-second quiet flow and no replay clients. Finish can
  retry `finishing`, `stop-failed`, `stopped` and returns a bounded 14-day
  idempotent completion receipt. Idle reap requires terminal recorded owner,
  7200-second quiet flow and reservation, no browser and no replay TCP clients,
  rechecked under lock. No owner proof means no automatic shutdown. A running
  browser can be reused only with a reachable external endpoint or exact live
  task unit generation and unchanged imported CA SHA-256. No daemon timer.
- Repair test receipt: `env -u HARNESS_BOUNTY_ARTIFACT_ROOT python -m pytest -q agents/test_browser_provisioner.py agents/test_chromium_test_launcher.py agents/test_browser_selection.py agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_startup_diagnostics.py --basetemp=/home/ryushe/.hermes/profiles/bugfix/cache/scratch/p1suite4` — **193 passed**. Environment unsetting is necessary because the runner inherited a scratch artifact override; launcher fixture expects the default `/mnt/bounty`.
- Interrupted-start repair: `task-proxy-recover` and `reap-idle` reconcile only same-agent/run `starting` browser intent after the **exact** browser unit reports `inactive`/`failed` twice, any launch-receipt PID is absent, any recorded process identity is terminal, and recorded loopback CDP is unreachable. This updates only the browser manager row to `stopped` under the node lock; it neither stops that browser unit by name nor releases/marks the profile lease healthy. The proxy still follows invocation verification, quiet-flow/client checks (for live startup), CA cleanup and indexing. Active/unknown units and live/unknown processes or ready CDP retain the reservation. Ordinary `task-proxy-finish` continues to reject a `starting` browser.
- Regression receipt: new cases cover interrupted start with both units inactive (with and without a launch receipt), unrelated active unit untouched, active or unverifiable browser unit refused, live/unknown PID or live CDP refused, and reaper's terminal-owner/quiet-flow gate plus active-unit refusal. `env -u HARNESS_BOUNTY_ARTIFACT_ROOT python -m pytest -q agents/test_browser_provisioner.py agents/test_chromium_test_launcher.py agents/test_browser_selection.py --basetemp=/home/ryushe/.hermes/profiles/bugfix/cache/scratch/o7` — **102 passed**; `env -u HARNESS_BOUNTY_ARTIFACT_ROOT python -m pytest -q agents/test_browser_resources.py agents/test_browser_lease_recovery.py agents/test_browser_startup_diagnostics.py --basetemp=/home/ryushe/.hermes/profiles/bugfix/cache/scratch/o2` — **101 passed** (203 total). The first latter run with a longer basetemp yielded `AF_UNIX path too long` in an unchanged fixture; the short physical scratch path passed.
- Merge/ancestry: branch based on `af9dae9` beta; no merge performed.

## Blockers and deferred work

- **Headed/manual smoke deferred:** `kasmvncserver`, `Xkasmvnc`, and `vncserver` are absent on this node (Xvfb alone cannot prove the native KasmVNC handoff). The D-Bus override also suppresses browser session-bus/portal integration; preserve existing display/manual arguments, but do **not** activate the headed/manual lane until a disposable KasmVNC manual-input session on the intended node proves readiness, display/input, root+renderer cgroup bounds, and terminal release/finish. Trigger when a usable headed KasmVNC stack is available. A failed headed startup must not be interpreted as successful manual handoff; do not remove the per-browser override to make it start.
- **Independent review:** review feature diff and intended beta integration suite before merge. No merge/push or runtime activation was performed in this handoff.
- **Recovery boundary:** active task replay has no authoritative client lease; the
  reaper uses terminal recorded owner, quiescence and socket absence, and is
  invoked only by `reap-idle` (no timer). A live interrupted startup without
  a recorded invocation cannot be stopped safely; reservation remains until
  the unit exits or an operator reconciles the exact process. Existing
  ownerless reservations are never auto-reaped.

## Interruption / resume handoff

- **Branch/ref:** `feat/browser-provisioner-mitm-auto-v2`
- **Checkpoint:** `59a525e` before orphan-start repair; the resulting repair commit is the next recoverable checkpoint.
- **Exact resume point:** independent diff review of interrupted-start safety, then disposable headed KasmVNC/native manual-input smoke when the headed stack is installed on the intended node. Headless proxy, CA, cgroup, release/replay/finish gates are green. Parent decides integration only after review; this subagent does not merge/push.
- **Working tree:** commit task-owned repair and dossier, then verify clean status.

## Decision gates

- **Integration:** focused suite green; independent review and intended beta integration checks pending.
- **Activation:** headless disposable browser cgroup and browser-origin proxied HTTPS flow proven; headed/manual KasmVNC unavailable and not verified on this node.
- **Promotion:** separate stable review, not implied by this feature.

## Decision record

- 2026-09-23 — forward-port on current beta lifecycle rather than copy obsolete provisioner; runtime activation held pending current-node evidence.
