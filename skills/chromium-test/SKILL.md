---
name: chromium-test
description: "Launch an isolated Chromium test browser on a free local CDP port for scoped web, desktop, or proxy-observed bug bounty workflows."
---

# Chromium Test

Use when an authorized security-testing task needs a fresh Chromium/Chrome
instance with remote debugging, an isolated profile, and its task-owned MITM
proxy. Ordinary browsing, documentation lookup, and unrelated UI automation
use Hermes's managed browser provider without a security proxy.

Use this for scoped live application exploration, not as the default replay
transport. A generic request to look up a URL is ordinary browsing, not an
implicit security engagement. For a scoped security flow, request the browser
through the provisioner; it starts the task MITM and imports its exact CA
before launching Chrome, so the agent can inspect its own traffic.

Also use this when a deep-map, URL-list, or raw replay run hits
Cloudflare/managed challenge pages, browser-only tokens, TLS/header fingerprint
issues, or other bot-defense behavior before app content is visible. A plain
403/401 is not enough by itself; classify normal app/server forbidden responses
with `/403`, `/error-triage`, auth, access-control, or header reasoning first.
For real challenge/fingerprint/browser-only cases, escalate into a proxied
browser context instead of treating raw HTTP as app-layer coverage.

The launcher prefers Playwright's bundled Chromium when Playwright is installed, then falls back to system Chromium/Chrome.

## Required browser admission

Codex, Claude, and other Ghost Home task agents must request every real
security-testing browser through `browser_provisioner.py`. It gives each run capacity admission, a
recorded owner, and a terminal lifecycle; named color/account profiles
additionally receive their exact lease. The alias must resolve exactly from the
program inventory—never derive an alias by adding a suffix such as `green2`.

`chromium_test.py` is exclusively the provisioner's implementation launcher.
Every real direct invocation fails before allocating a port, profile, or
Chromium process. `--dry-run` remains available for implementation planning and
focused launcher tests. Hermes ordinary browsing uses its own managed browser
provider rather than Chromium Test.

IDOR is replay-first after a browser-derived session/request has been captured:
stop and release the browser/profile at that point unless further browser work
is necessary, then build and run bounded direct replays through the task MITM
lane. A stored session supports replay; it is not a reason to leave a browser
or its profile lease running.

## Hoster GPU-Backed Headed Escalation

When a genuine bot challenge or browser-fingerprint block prevents normal scoped
coverage, Hoster is the preferred escalation target: it has a GTX 1070 Ti
exposed through Mesa/Nouveau and can run a real, **headed** Chromium process.
Use this to reduce automation/fingerprint mismatch; it is not a guarantee of
passing a challenge and must not be used to evade program rules or access
controls.

1. Keep the default headed mode: do **not** pass `--headless`. Connect to the
   returned CDP endpoint from the automation client or a permitted manual
   display workflow. Completion: the launch plan has no `--headless` flag.
2. **Route to Hoster deliberately.** If the agent is already on Hoster, launch
   locally only from a Hoster user-systemd service. If it is on another machine,
   use the canonical `hoster-ssh` dispatch helper—not a raw remote launcher or
   interactive SSH shell. Completion: the launcher reports `runtime: hoster`,
   a Hoster-local profile/CDP endpoint, and a ControlGroup outside
   `ssh.service`.
3. Request via the canonical provisioner *on Hoster*, with a unique run ID and
   Hoster-local proxy (`http://localhost:<leased-port>`). Use an ephemeral
   profile only where the engagement does not need a named account profile. Do
   not launch raw Chrome, reuse an existing Chrome process/profile, or invoke
   `chromium_test.py` directly from an SSH cgroup: bypassing engagement
   admission and ownership is unsafe.
4. Before treating the run as GPU-backed, verify its recorded browser PID owns
   `/dev/dri/renderD128` and that `eglinfo -B` reports `NV134`, rather than
   `llvmpipe`. `nvidia-smi` is not the verification path here: this host uses
   the Nouveau driver and may not provide it.

5. Revisit the blocked URL once in that browser and capture only sanitized
   observations (challenge/app content visible, request shape, screenshots).
   If it remains blocked, record that outcome and stop escalation rather than
   retrying indiscriminately.
6. Follow the normal Hoster lifecycle contract: stop the recorded browser root,
   confirm CDP is closed, remove the run profile, and release its MITM lane.

### GPU/WebGL in-page verification and re-provisioning on bot blocks

Process-level GPU checks are **not sufficient**: a run can hold
`/dev/dri/renderD128` with `eglinfo -B` reporting `NV134` while the page itself
still has **zero WebGL** (`canvas.getContext('webgl')`/`'webgl2'` both `null`,
`chrome://gpu` empty). Bot-scoring SDKs treat "no WebGL whatsoever" as a
headless/automation signal, because almost no real desktop browser presents it.
Observed consequence: a bot-score style rejection — token issued through a
fully clean flow (`/init`, `/init/execute`, captcha `getcaptcha`, batch all
2xx) and then silently rejected with `403 Captcha token validation failed`, no
challenge displayed — purely because the provisioned browser had no WebGL.
The same flow passed in Ryushe's ordinary browser, and went **403 → 201** in
the provisioned browser once WebGL was exposed as the only changed variable.

When a scoped run hits a bot blocker, managed challenge, or that silent
bot-score rejection pattern, and program rules and rate limits allow continued
work:

1. **Suspect missing GPU/WebGL first.** Verify **in-page**, not at process
   level, via CDP:
   ```js
   const c = document.createElement('canvas');
   const gl = c.getContext('webgl2') || c.getContext('webgl');
   const d = gl && gl.getExtension('WEBGL_debug_renderer_info');
   ({webgl: !!gl, renderer: d && gl.getParameter(d.UNMASKED_RENDERER_WEBGL)})
   ```
   If `webgl` is `false`, the environment — not the request shape or payload —
   is the likely cause.
2. **Re-provision rather than debug in place.** Return the current browser
   through its normal lifecycle, then re-request through
   `browser_provisioner.py` with GPU/WebGL exposure active: set
   `CHROMIUM_TEST_CHROME` to a GPU-wrapper chrome shim in the Hoster
   user-manager environment before the request, and unset it afterwards:
   ```bash
   systemctl --user set-environment CHROMIUM_TEST_CHROME=<path-to-gpu-wrapper-shim>
   # ... browser_provisioner.py request ... (launch record command[0] == the shim)
   systemctl --user unset-environment CHROMIUM_TEST_CHROME
   ```
   The shim must resolve a real Chrome binary and prepend GPU-enabling flags
   (`--use-gl=angle --use-angle=gl --ignore-gpu-blocklist
   --enable-gpu-rasterization --enable-unsafe-swiftshader`) before the
   launcher's argv. Do not work around a bad environment by mutating requests:
   while WebGL is missing, **every** write fails identically — including a
   no-modification control — so a bot-score rejection is not evidence about
   your payload and any control run in that state is confounded.
3. **Re-verify in-page after re-provisioning.** Assert `webgl: true` and a
   present renderer string before retrying the blocked flow (a truthful
   `llvmpipe` software renderer is acceptable; it is what KasmVNC GLX
   provides). If the surface still rejects after WebGL is real, stop
   escalating: record the outcome and hand the interactive flow to Ryushe via
   the KasmVNC handoff instead of moving toward evasion.
4. **Environment repair only.** This exposes the GPU/WebGL capability the
   machine actually has and reports a truthful renderer string. Do not extend
   it into fingerprint spoofing, stealth patches, faked renderer strings,
   CAPTCHA-solving services, or IP rotation — those remain prohibited.

### Remote CDP Navigation from Ghost

The remote browser and the agent navigation client are separate processes:

1. Start the headed Chromium process on Hoster under its recorded task owner
   (the launcher/supervisor). It survives a one-shot SSH launch command; the
   SSH process that starts it does **not** need to remain open.
2. Chromium deliberately binds CDP to `127.0.0.1:<remote-cdp-port>` on Hoster.
   From Ghost, create one tracked SSH local-forward for the active navigation
   period, mapping `127.0.0.1:<local-cdp-port>` to that remote endpoint:
   ```bash
   ssh -i /home/ryushe/.ssh/hoster -N -T \
     -o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=no \
     -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
     -L 127.0.0.1:<local-cdp-port>:127.0.0.1:<remote-cdp-port> \
     ryushe@hoster
   ```
   Start this as a tracked background process, record its local PID, and keep
   it only while Ghost needs to drive the browser. Never bind CDP to `0.0.0.0`.
3. Connect the Ghost-side CDP-aware browser client (or a local Playwright
   client) to `http://127.0.0.1:<local-cdp-port>`. For Hermes native CDP tools,
   establish the forward before the new session or use `/browser connect` to
   attach it. Completion: `http://127.0.0.1:<local-cdp-port>/json/version`
   is reachable from Ghost, using the recorded generation path in the forwarded URL for fenced browsers.
4. If the forward drops, the Hoster browser may still run but Ghost can no
   longer navigate it; create a replacement forward to the same recorded CDP
   port, rather than launching a second browser. On completion, close the
   tunnel by its recorded local PID, then perform normal Hoster browser/lane
   cleanup.

Example preflight (read-only; never inspect or terminate unrelated browsers):

```bash
ssh -i /home/ryushe/.ssh/hoster -o BatchMode=yes -o ConnectTimeout=10 \
  -o ControlMaster=no -T ryushe@hoster \
  'eglinfo -B | grep -E "renderer|NV134"; fuser -v /dev/dri/renderD128'
```

## Task-owned browsers and lifecycle recovery

For ordinary website browsing and authentication outside a security engagement,
use Hermes's managed browser provider with no security proxy. If an authorized
BBH task specifically requires a provisioner-owned general-purpose browser,
request `--task-owned` without program/account selectors and explicitly pass
`--proxy none` for non-security use. This isolates the profile by agent/run; it
does not select inventory credentials or combine authorization scopes. A
security-testing `--task-owned` request keeps the default task MITM. See
[provisioner commands and lifecycle](scripts/README.md#browser_provisionerpy).

Fresh provisioner requests default to agent-driven control, including headed
security browsers. Meaningful managed browser activity protects the control claim;
health checks, automatic heartbeats and a living agent PID do not reset idle age.
Agents still request the explicit account/color (for example Blue); only the
browser instance slot is automatic. Reuse the matching agent/run's browser or
allocate a distinct instance when policy permits and node admission has room.
Do not take another agent's idle browser merely to reuse it. Idle takeover is
eligible after five minutes (300 seconds by default), only under the resolved
program/account/domain single-browser policy, legacy exclusive-profile contract,
or insufficient node headroom. The old owner's configured threshold cannot be
shortened by the requester. Active, in-flight, held or unobservable browsers
remain protected; unavailable capacity/ownership queues rather than changing
account. Explicit slots and legacy profiles are not silently migrated.
The separate two-hour request-triggered cleanup still retains profile state.

The optional `--owner-pid <local-task-supervisor-pid>` also supplies an explicit
terminal task signal. It must cover the task lifetime on the browser node,
not this request command, a remote process, or a shared daemon. Legacy,
untracked and manual-mode records remain conservative; missing telemetry is
not evidence of idleness.

A reclaimable healthy matching headless profile may transfer without restarting
Chromium after its configured inactivity window. The provisioner fences old
controller sockets and URLs before transferring the lease. In-flight operations
and bounded intervention holds protect against takeover and cleanup. Live
transfer requires explicitly browser-owned fixed proxy routing; task-owned
proxy routes, all headed/native displays (including non-Kasm sessions), and
legacy unfenced browsers require verified restart instead.
Do not relabel a task proxy as browser-owned to obtain live reuse. Preserve the
full generation-path control URL from the private launch record; a bare port is
not a usable replacement. Fencing is an operational boundary, not isolation
against hostile same-UID processes.

Use provisioner `touch --work-state awaiting-input --awaiting-seconds N` for a
bounded manual wait (default 1800 seconds, maximum 3600). Repeated waiting
touches do not extend the absolute deadline. Explicit release still supports
early task completion; persistent profile state survives browser cleanup.

## Invocation

### From Ghost or another machine

Use `hoster-ssh` to place the provisioner request in a named Hoster
user-systemd service. The provisioner starts the browser under its own recorded
user-systemd unit; a `queued` result is normal admission control, not a reason
to bypass it with a direct launcher invocation.

Use the portable `hoster-ssh` skill interface to create the named remote
user-systemd unit. Do not substitute a machine-local helper path or directly
invoke an unrecorded remote launcher. The unit must run:

```bash
bbh skills/chromium-test/scripts/browser_provisioner.py request <program> <account> \
  --agent-id <agent-id> --run-id <run-id> --purpose '<task>' --url '<url>'
```

Read the provisioner result from the recorded request unit. It returns safe
lease/browser metadata only; use the owner-recorded local control path rather
than printing or sharing CDP endpoints:

```bash
ssh -i /home/ryushe/.ssh/hoster -o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=no -T \
  ryushe@hoster "export XDG_RUNTIME_DIR=/run/user/\$(id -u); export DBUS_SESSION_BUS_ADDRESS=unix:path=\$XDG_RUNTIME_DIR/bus; journalctl --user -u '$unit' --no-pager -n 40"
```

After dispatch, verify the unit ControlGroup is outside `ssh.service` before
opening a temporary CDP forward. Reuse a healthy matching run when its recorded
run ID, CDP endpoint, profile, and unit all match; do not launch a duplicate
browser merely because a prior task's process is old.

### Local Hoster invocation

```text
bbh skills/chromium-test/scripts/browser_provisioner.py request \
  <program> <account> --agent-id <agent-id> --run-id <run-id> \
  --purpose "<task>" --url <url>
```

### KasmVNC manual-display handoff

**Manual-authentication selection rule:** for a user-operated login, password
entry, MFA, OAuth popup, wallet connection, CAPTCHA, or other interactive
browser flow, launch or reuse an isolated browser with `--display-backend auto`
**before** creating any handoff. `auto` attempts the required KasmVNC graphical
handoff first and produces a receipt if it must fall back; use strict
`--display-backend kasmvnc` only when a KasmVNC-only failure is intended. A
screenshot/CDP handoff is not an acceptable default
because it is materially worse for focus, popups, password managers, and other
interactive UI. Do not first launch Xvfb/headless and then retrofit a screenshot
handoff just because the browser is already running.

A screenshot/CDP handoff is otherwise limited to a non-login visual inspection.
For an interactive authentication flow, it is allowed only when **KasmVNC is
unavailable or its required CDP readiness check fails**. Retain the launch
receipt's `display_fallback` failure reason and verify the same task MITM gate:
`proxy_cert_mode: import` and `proxy_cert_status.status: trusted`. Do not use a
stale non-graphical browser, a convenience preference, or prior approval as a
substitute for that recorded KasmVNC failure. This creates a dedicated KasmVNC
display and a loopback-only HTTP viewer while CDP remains on `127.0.0.1`:

```bash
bbh skills/chromium-test/scripts/browser_provisioner.py request \
  <program> <account> --agent-id <agent-id> --run-id <run-id> \
  --purpose "manual handoff" --url https://target.example/ \
  --display-backend kasmvnc --kasmvnc-display 20 --kasmvnc-web-port 8463
```

The JSON record includes `kasmvnc.web_url` (`http://127.0.0.1:<port>/`) and a
scoped `kasmvnc.stop_command`. Use only a task-specific **Tailscale Serve**
route to terminate HTTPS in front of that local HTTP endpoint; never use
Funnel or a public/LAN listener. Stop the recorded KasmVNC display after the
handoff alongside the browser and profile cleanup.

## MITM Proxy Certificate Handling

The provisioner defaults to `--proxy mitm`: it reserves a task/run-specific
loopback listener in 8081–8090, waits for its private CA, and passes both to
the launcher before Chromium spawns. The launcher imports that CA into the
isolated profile; readiness requires a trusted import receipt. Browser release
does **not** stop the task proxy: direct replay may continue through the
returned `task_proxy.proxy_server` using `task_proxy.ca_cert` as the origin CA
(`curl --cacert`, not `--proxy-cacert`). At task completion:

```bash
bbh skills/chromium-test/scripts/browser_provisioner.py task-proxy-status --agent-id <agent-id> --run-id <run-id>
bbh skills/chromium-test/scripts/browser_provisioner.py task-proxy-finish --agent-id <agent-id> --run-id <run-id>
bbh skills/chromium-test/scripts/browser_provisioner.py task-proxy-recover --agent-id <agent-id> --run-id <run-id>
```

Finish rejects an active/starting browser, verifies listener stop, removes only
matching task CA trust from stopped persistent profiles, then indexes the
private flow. Stop/index/CA errors retain the reservation for recovery. If
startup was interrupted or cleanup failed, `task-proxy-recover` retries after
the browser stops. A live listener additionally needs its recorded unit
generation, 7200 seconds of quiet flow and no connected replay clients; an
unverified live listener is never stopped. Finish is retryable after stop, CA cleanup,
or indexing failure and returns `already_finished` for a completed run.
`reap-idle` can close an orphan listener only after 7200 seconds of quiet flow,
terminal recorded owner identity, no active browser, and no connected replay
client; ownerless runs require explicit finish/recovery. No timer is installed.
Reuse probes the live external endpoint and compares imported CA fingerprints,
not merely the recorded CA path. If a
later task replaced the NSS nickname with its different CA, finishing the older
task skips that nickname without deleting later trust. Use
`--proxy external --proxy-server <listener> [--mitm-ca-cert <CA>]` only for explicitly managed
external routing; use `--proxy none` for explicit direct traffic (Chromium
receives `--no-proxy-server`). Neither mode consumes a task listener. A running
browser cannot be hot-rerouted. No shared Caido/default proxy fallback is
permitted for a failed task listener. Verify browser-origin HTTPS flow capture
and the root/renderer cgroup before declaring a host runtime active.

The launcher should trust the proxy CA inside each isolated Chromium profile.
Do not use blanket certificate-ignore mode as the normal path.

Default behavior:

- `--proxy-cert-mode import` is the default: require the mitmproxy CA import and fail before launch if it cannot be prepared.
- `--proxy-cert-mode auto`: explicit disposable debugging mode only; it may fall back to `--ignore-certificate-errors` when `certutil` or the CA file is missing.
- `--proxy-cert-mode ignore`: explicit disposable debugging mode.
- `--proxy-cert-mode none`: attach the proxy without CA setup or ignore flags.

Standalone profile preparation:

```bash
bbh skills/chromium-test/scripts/install.sh
bbh skills/chromium-test/scripts/mitm_chromium_profile.py \
  --profile-dir "$HARNESS_SHARED_BASE/<program>/ghost/chromium-test/profiles/<account>" \
  --home-dir "$HARNESS_SHARED_BASE/<program>/ghost/chromium-test/profiles/<account>/home" \
  --ca-cert ~/.mitmproxy/mitmproxy-ca-cert.pem
```

Legacy standalone Hoster proxy tooling (implementation/recovery only, not the
agent's security-browser route):

- `http://hoster:8080` may exist as a legacy shared listener, but agents must
  not use it for active security browser or direct replay traffic. Its explicit
  legacy maintenance command is:
  ```bash
  bbh skills/chromium-test/scripts/hoster_mitm_lane.py --json ensure-default
  ```
- `http://hoster:8081` through `http://hoster:8090` are leased per-agent MITM
  lanes. Acquire a lease before starting a task-specific proxy and release it
  after indexing the lane into the central proxy store.
- On Ryushe's PC (`abommie`/`ryushespc`), prefer the local MITM proxy lane
  unless the task explicitly asks for Hoster routing.

Lease-backed mitmproxy lane smoke:

```bash
bbh skills/chromium-test/scripts/hoster_mitm_lane.py --json acquire-start \
  --agent-id <agent-id> \
  --run-id <run-id> \
  --program <program> \
  --task "<task>" \
  --account-label <account-label>
```

> **Implementation-only smoke test — not an agent launch instruction.** This
> directly invokes the provisioner's internal launcher only for provisioner
> implementation tests. Task agents must use `browser_provisioner.py request`.
>
```bash
bbh skills/chromium-test/scripts/chromium_test.py <program> "<task>" \
  --proxy-server http://hoster:<leased-port> \
  --ephemeral-profile \
  --run-id <run-id> \
  --agent-id <agent-id> \
  --account-label <account-label> \
  --proxy-cert-mode import \
  --mitm-ca-cert ~/.local/state/ghost/mitm-lanes/<lane>/mitmproxy/mitmproxy-ca-cert.pem
bbh skills/chromium-test/scripts/hoster_mitm_lane.py --json index-stop-release \
  --lane <lane> \
  --agent-id <agent-id> \
  --run-id <run-id> \
  --account-label <account-label> \
  --proxy-port <leased-port> \
  --transport browser
ssh -i /home/ryushe/.ssh/hoster -o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=no -T \
  ryushe@hoster 'bbh skills/chromium-test/scripts/proxy_store.py query --program <program> --method POST'
bbh skills/chromium-test/scripts/proxy_store.py export-request --id <request_id> --output /tmp/request-packet.json
bbh skills/chromium-test/scripts/chromium_test.py cleanup-profile --profile-dir <profile-dir> --json
```

## Required Preflight

1. Read program scope/rules and the interpreted rate limit before live interaction.
2. Read `prompts/chromium-test-playbook.md`.
3. Check existing program context under `$HARNESS_SHARED_BASE/{normalized-program}/`.
4. Resolve browser/account state from explicit task context or a locked-down auth seed file. Do not query external profile services during browser launch.
   - If `--auth-seed-file` is not provided, `--account <alias-or-color>` or
     `--account-label <alias-or-color>` may resolve
     `$HARNESS_SHARED_BASE/{normalized-program}/credentials/account_inventory.json`.
     `normalized-program` lowercases the selected program and converts
     separators to `-`; it is not a browser-lane or general inventory path.
   - Account inventory entries are non-secret pointers only. They may include
     `credential_ref` or `auth_seed_ref` values such as
     `auth-seed:/absolute/path/to/seed.json`, but never cookie/token/header
     values.
   - When a selected account needs authentication and has no usable stored auth
     seed, automatically refresh only that exact account when its program record
     permits `auth_refresh_source=ryushe-proxy`. Existing auth seeds are never
     reset or replaced merely because the launcher starts.
   - If the proxy is unavailable or has no matching usable evidence, lease and
     provision the exact account's browser profile for its existing session or
     browser-native login. If that cannot establish a usable session, retain the
     exact lease as `awaiting-input`, publish only its loopback UI through
     task-scoped Tailscale Serve with the SSH-loopback fallback, and pause for
     Ryushe. The handoff message must identify the resolved session account,
     state the attempted safe login/auth-check failure, include the actual
     Tailnet URL and scoped SSH fallback, and list freshly queried safe account
     availability (use `status {program} --idor` for IDOR/BOLA). Never print or
     persist raw values outside the locked-down seed file.
5. If Ryushe names an account/profile, for example "use blue to go look at X", use that scoped account context. If the needed account/profile is unclear, ask before borrowing or creating auth state.
6. If the task needs live intercept/modify/forward behavior, read
   `intercepted-proxy` before launching. The default provisioner listener is
   capture-only; require a verified temporary interception mechanism or use
   bounded replay/stop. Do not assume Caido Tamper is available on task MITM.
7. Confirm the MITM proxy setup:
   - For an authorized security-browser request, the provisioner defaults to
     `--proxy mitm`; use the returned task-owned proxy URL and CA on that
     browser node. Do not pass a legacy route-table/shared-8080 proxy.
   - Require `proxy_cert_mode: import` and `proxy_cert_status.status: trusted`
     before traffic. Explicit certificate-ignore mode is disposable debugging
     only, never an automatic fallback.
   - Ordinary browsing uses Hermes's managed browser without MITM. An explicit
     provisioner `--proxy none` forces direct Chrome routing but is not the
     default for security testing.
8. For curl-failure escalation, inject only approved agent-owned or auth-seed
   auth/session material into the browser context. Use it in memory only; never
   print, store, or summarize raw cookies, bearer tokens, CSRF tokens, or
   private headers.

## Canonical Files

- Playbook: `prompts/chromium-test-playbook.md`
- Launcher: `skills/chromium-test/scripts/chromium_test.py`
- Persistent profile lease/status: `skills/chromium-test/scripts/browser_profile_lease.py`
- Script walkthrough: `skills/chromium-test/scripts/README.md`
- Profiles: `$HARNESS_SHARED_BASE/{program}/ghost/chromium-test/profiles/`
- MITM profile helper: `skills/chromium-test/scripts/mitm_chromium_profile.py`
- MITM lane helper: `skills/chromium-test/scripts/mitm_lane.py`
- Hoster lane helper: `skills/chromium-test/scripts/hoster_mitm_lane.py`
- Sanitized proxy store: `skills/chromium-test/scripts/proxy_store.py`
- Dependency installer: `skills/chromium-test/scripts/install.sh`
- Notes/evidence: `$HARNESS_SHARED_BASE/{program}/ghost/chromium-test/`

## Workflow

0. For every bug-bounty browser engagement, request the browser through the
   provisioner. If it requires a durable named account profile (for example a
   color used across a multi-agent owned-account test), first run
   `browser_profile_lease.py status <program> --account <color> --auth-domain <auth-host>`, then acquire
   that **exact** account and auth domain if available. Omit `--auth-domain`
   only when the inventory's `auth_host_filter` is the intended auth surface.
   A lock is scoped to the resolved auth domain and exact account, so unrelated
   domains may use their own persistent profile for the same color. A locked
   response may show safe, explicitly available alternatives but never
   authorizes automatic account substitution. Run the helper on the browser
   profile host. Use the persistent account profile after acquisition; retain
   `--ephemeral-profile` for disposable one-off runs. A lease remains locked
   while work awaits input: renew it with `--work-state awaiting-input`; only a
   terminal completion, handoff, or cancellation may call `release`, which must
   declare a non-secret `--profile-health` for the next agent.
1. Request the engagement browser through the provisioner:
   ```bash
   bbh skills/chromium-test/scripts/browser_provisioner.py request \
     <program> <account> --agent-id <agent-id> --run-id <run-id> \
     --purpose "<task>" --url <url>
   ```
   On `queued`/`queued-timeout`, preserve the exact task and account, perform
   only non-browser preparation, and retry with bounded backoff. Never launch
   `chromium_test.py` directly to evade engagement admission. On `started` or
   `already-running`, use the browser's owner-recorded control path and returned
   `task_proxy` metadata. The provisioner starts the task MITM and passes its
   exact proxy URL and CA to the launcher before Chrome starts.
2. Use the owner-recorded browser control path to connect browser automation or
   manual debugging; do not disclose or borrow another agent's CDP endpoint.
3. For challenge/fingerprint/browser-only escalation, revisit the blocked URL in
   this browser profile before running more probes. Confirm whether the app
   layer, JS, route params, and proxy-observed requests are now visible.
4. Perform only the requested scoped action in that browser profile.
5. Observe this run's restricted task flow file while driving. For direct
   replay, use the returned `task_proxy.proxy_server` and trust its
   `task_proxy.ca_cert` as the origin CA. After `task-proxy-finish` indexes the
   capture, query sanitized request metadata or export a local replay packet:
   ```bash
   bbh skills/chromium-test/scripts/proxy_store.py query --program <program> --method POST
   bbh skills/chromium-test/scripts/proxy_store.py export-request --id <request_id> --output /tmp/request-packet.json
   ```
6. Release the browser through `browser_provisioner.py release` and verify the
   recorded root and CDP endpoint close; persistent account profiles remain.
   Dispose of a task-only profile only after its root is stopped and it is no
   longer in use. Never infer cleanup from directory deletion alone.
7. Continue bounded direct HTTP replay through the same task MITM when needed.
   At task completion call `browser_provisioner.py task-proxy-finish --agent-id
   <agent-id> --run-id <run-id>`; it stops and verifies the listener, removes
   matching task CA trust from stopped profiles, indexes flows, and releases
   the port. Use `task-proxy-recover` only for an interrupted/failed cleanup.
8. Save screenshots, request notes, and reproduction details under the program evidence directory.

### Hoster Lifecycle Contract

When the browser runs on Hoster, assign a unique run ID and record the root browser PID, CDP port, profile path, and owning tmux session or service before connecting automation. Do not leave browsers unmanaged merely to preserve a reconnect option. The provisioner owns the bounded recovery grace and may hand off a healthy matching browser after fencing the terminal owner; outside that path, terminal cleanup stops it while preserving its persistent profile.

Do not start raw Chrome from a detached shell as the default path. Use the canonical launcher; if a raw launch is necessary, give it a bounded timeout or an explicit teardown command tied to the recorded root PID. A completed, failed, or superseded task must terminate its named tmux session/service after browser cleanup. Never use broad `pkill chrome` or unscoped tmux cleanup.

### Required Exit Verification

A run may claim browser-process cleanup only after the first two are recorded.
For a disposable task-only profile, also verify the third; persistent named
account profiles intentionally remain after release:

```text
root browser PID: stopped
CDP endpoint: closed/unreachable
disposable run-scoped profile directory: absent (if deletion was requested)
```

Never delete a persistent account profile as part of ordinary browser release.
If a disposable-profile cleanup helper removes its directory while its
Chromium root is still alive, treat cleanup as incomplete: stop the exact root,
confirm CDP is closed, and recheck disposable directory absence.

## Guardrails

- Core posture: scoped testing is allowed; damaging behavior is explicit.
- Never reuse Ryushe's normal browser profile.
- Never print secrets, cookies, or credentials in chat.
- Never paste exported full proxy request packets into prompts or chat; they
  may contain cookies, bearer tokens, CSRF values, API keys, or request body
  secrets. Use sanitized query output for agent context.
- Auth seed files must be local JSON files with owner-only permissions such as
  `0600`. The launcher may report safe metadata and which secret field names
  exist, but must never print cookie, bearer, CSRF, or token values.
- Verify the launcher output or the local Chromium root-process command includes `--proxy-server=<browser-proxy>` and that `proxy_cert_status` is `trusted` when proxy TLS interception is expected. Do **not** infer a missing proxy from CDP `Browser.getBrowserCommandLine`: Chrome returns that command only when started with `--enable-automation`. If the launcher falls back to `--ignore-certificate-errors`, record that as debug/fallback behavior.
- Live browser traffic should be observed from this browser's MITM proxy lane. Do not pull live browser requests from Ryushe's proxy unless Ryushe specifically asks for Ryushe-lane comparison or request lookup.
- Named-account auth refresh is automatic when Ryushe asked for that account
  (for example "blue credentials"), no usable seed exists, and the account
  inventory permits `auth_refresh_source=ryushe-proxy`. It refreshes only that
  account's seed and does not reset an existing seed. If no usable evidence can
  be pulled, use the exact account's browser profile; if login still needs
  Ryushe, hand over the private Tailscale Serve login UI plus SSH fallback. Test
  through the agent MITM lane after authentication succeeds.
- Direct HTTP replay is preferred after a live request is captured and should use `curl -x <mitm-proxy>` when request logging is desired.
- For intercepted proxy testing, require the provisioner's task MITM and CA
  receipt before traffic. Route to `intercepted-proxy` to check whether an
  actual live-intercept mechanism is supported; default capture-only mitmdump
  does not provide intercept on/off or a Tamper API. Replay safely or stop.
- Stay inside the program scope, account authorization, and rate limits.
- For state-changing tasks, confirm the action is allowed and non-destructive before proceeding.
