# Chromium Test Scripts

## Inventory

- `browser_provisioner.py` — canonical admission, profile-lease, and Chromium
  request path.
- `chromium_test.py` — isolated Chromium launcher used by the provisioner.
- `browser_profile_lease.py` — exclusive owned-account/profile lease registry.
- `browser_control.py` — internal Chromium pipe/CDP adapter and control fencing.
  Its private mode-0600 Unix socket also provides read-only `GET /identity`:
  exact `process_identity`, current generation `cdp_url`, and `available`
  (false during freeze/rotation). This is for exact local handoff validation,
  not a public status endpoint: the URL is a capability and must not be logged
  or exposed by consumers. It makes no CDP call and does not update activity.
  The existing same-UID trust boundary is unchanged. Deterministic verification:
  `agents/test_cdp_handoff_receipt.py::test_private_bridge_identity_is_passive`.
- `browser_lifecycle.py` — node-local process identity, locking, atomic private records,
  and bounded opt-in startup metadata (contract below).
- `kasmvnc_session.py` — task-owned headed display lifecycle.
- `mitm_lane.py` — local task MITM lane lifecycle.
- `hoster_mitm_lane.py` — bounded Hoster-backed MITM lane lifecycle.
- `proxy_store.py` — sanitized SQLite index for captured lane traffic.
- `mitm_chromium_profile.py` — imports the selected MITM CA into one Chromium
  profile.
- `install.sh` — explicit package-manager installer for the required `certutil`
  dependency; review before running because it invokes system package tooling.

Use the detailed records below for supported invocation and safety boundaries.
Each helper owns deterministic mechanics only; lane availability, account
selection, target scope, and browser state still require agent verification.

## Opt-in private startup diagnostics

Set `BROWSER_STARTUP_DIAGNOSTICS=1` on a provisioner request to write metadata
under `<BROWSER_PROVISIONER_STATE parent>/startup/<browser UUID>/`. The manager
passes its task-owned directory via internal `BROWSER_STARTUP_RECEIPT_DIR`;
ordinary stdout/API receipts and the 45-second publication deadline are unchanged.
The owning `browser_lifecycle.py` helper writes atomic mode-0600 snapshots in
mode-0700 attempt directories (manager, launcher and exec components, maximum
32 events each). Events contain fixed phase/outcome/error categories, monotonic
start/elapsed times and, where available, a numeric process return code.

Chromium stderr is drained in 4-KiB chunks and counted up to 64 KiB. **No stderr
content is collected**: byte counts prove output occurred, not why it failed.
There is no regex-redaction claim or persistence of command lines, URLs, tokens,
cookies, credentials, exception text, or protocol bodies. Missing/failed metadata
writes do not replace the launch result. An absent launcher receipt can still
mean failure before launcher entry; metadata is diagnostic evidence, not a root
cause or a liveness guarantee. Snapshots are bounded per attempt, not an automatic
retention service; remove task-owned receipts after investigation as appropriate.

The opt-in disposable systemd fixture enables this automatically. It retains a
schema-projected receipt in a separate private `bbh-startup-evidence-*` directory,
including on failure, before deleting any profile. It stops only UUID units
found in its own disposable registry/launch/startup files, including attempts
that failed before registration. Unit inactivity, recorded root death, recorded
loopback CDP closure, and absence of processes referencing its disposable root
are checked before deletion; failed cleanup retains the root and evidence.

Verification: `agents/test_browser_startup_diagnostics.py` covers timeout,
malformed publication, dispatch/registration failure, real exec failure,
saturated stderr, private modes, disabled/unwritable diagnostics, failure-evidence
survival and failed-stop retention. Run the existing disposable fixture with
`BBH_LOCAL_BROWSER_SMOKE=1`; it never needs a live site or account.
Last verified: 2026-09-21. Owner/scope: Chromium Test startup/lifecycle plumbing.

## `kasmvnc_session.py`

- **Purpose:** Starts, checks, and stops one task-owned KasmVNC display for a
  headed Chromium manual handoff. The helper selects a free local HTTP port
  when requested with `--web-port` omitted and records only display/port
  metadata under the supplied state directory.
- **Inputs:** `start`, `status`, or `stop`, display/port controls, and the
  task-owned state directory.
- **Outputs:** JSON session status and loopback KasmVNC metadata.
- **Mutates:** The selected task-owned display process and state directory for
  `start` and `stop`; `status` is read-only.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_chromium_test_launcher.py -q`
- **Owner/scope:** Chromium Test skill.
- **Last verified:** 2026-09-10.
- **Security:** The KasmVNC endpoint is loopback-only (`127.0.0.1`) and uses
  HTTP. When remote access is required, publish that local port through a
  task-specific Tailscale **Serve** route, which terminates HTTPS; never use
  Funnel or a public/LAN listener. CDP remains loopback-only and is not
  published through KasmVNC.
- **Walkthrough:**

  ```bash
  bbh skills/chromium-test/scripts/kasmvnc_session.py start --display 20 --web-port 8463 --json
  bbh skills/chromium-test/scripts/kasmvnc_session.py status --display 20 --json
  bbh skills/chromium-test/scripts/kasmvnc_session.py stop --display 20 --json
  ```

  The browser provisioner owns the bug-bounty engagement browser start path. It
  performs node-local admission and, for named color/account profiles, exact
  profile leasing before it invokes the Chromium launcher:

  ```bash
  bbh skills/chromium-test/scripts/browser_provisioner.py request \
    <program> <account> --agent-id <agent-id> --run-id <run-id> \
    --purpose "manual handoff" --url https://target.example/
  ```

  Every real Chromium Test browser run must use the provisioner. Hermes ordinary
  browsing uses its managed browser provider rather than Chromium Test. Direct
  calls reject before Chromium is created; `--dry-run` remains available for
  planning and focused launcher tests. Engagement handoff settings belong in the
  provisioner rather than creating a second direct-launch path.

  Its JSON result includes the loopback `kasmvnc.web_url` and an exact scoped
  `kasmvnc.stop_command`. The default display backend is unchanged; KasmVNC is
  used only with `--display-backend kasmvnc`.

## `browser_profile_lease.py`

Explicit `--instance-key` acquisitions add isolated parallel slots without
migrating legacy single-profile leases. Manual policy and passive reporting:

```sh
bbh skills/chromium-test/scripts/browser_profile_lease.py --state-dir <state> \
  set-browser-policy <program> <account> --auth-domain <domain> --mode single
bbh skills/chromium-test/scripts/browser_profile_lease.py --state-dir <state> \
  report-logout --lease-id <lease> --agent-id <agent> --reason user-observed
```

`single` is enforced transactionally for new acquisitions of the resolved
program/account/domain; `multiple` allows explicit independent slots. Policy
writes do not kill existing browsers. Reasons are `user-observed`,
`signed-out-ui`, or `session-rejected`; reports store no content, secrets or
URLs and never infer single-session behavior, change policy, retry auth or
create browsers. Released/handoff leases clear stale CDP/service metadata.
The older account-level views below remain conservative summaries, not a
multi-instance pane registry.

- **Purpose:** Coordinates one persistent Chromium profile per `program/auth-domain/account`
  on the machine that hosts that browser. It prevents two agents from driving the
  same account profile concurrently while exposing non-secret account capability
  metadata and explicitly available alternative accounts.
- **Inputs:** Program slug; owned account alias or PwnFox color; agent/run IDs;
  non-secret `account_inventory.json`; a local state directory on the profile
  host.
- **Outputs:** JSON lease/status records only. It never emits auth-seed paths,
  cookies, tokens, passwords, or private headers.
- **Mutates:** A local SQLite lease database under
  `~/.local/state/ghost/browser-profile-leases/` by default. It does not modify
  browser profiles or the account inventory.
- **Scope:** Run on the persistent-profile host (normally Hoster), not on a
  machine that merely forwards CDP to it.
- **Walkthrough:**

  ```bash
  # Ask by global principal tier; owner roles map to admin. Anonymous slots are
  # durable unauthenticated browser profiles, not account fixtures.
  bbh skills/chromium-test/scripts/browser_profile_lease.py status <program> --tier admin
  bbh skills/chromium-test/scripts/browser_profile_lease.py status <program> --anonymous

  # Request an exact anonymous profile to retain carts and other browser-only
  # state. It is exclusively leased but has no account record or auth seed.
  bbh skills/chromium-test/scripts/browser_provisioner.py request \
    <program> anon1 --agent-id <agent-id> --run-id <run-id> \
    --purpose "anonymous cart investigation"

  # Ask first for a named profile. This reports role, program-specific org/plan
  # access, capabilities, lock state, and probes a registered local CDP endpoint.
  bbh skills/chromium-test/scripts/browser_profile_lease.py status <program> --account green --auth-domain videogp.superdrug.com

  # Request exactly the selected account; the provisioner leases it and never
  # falls back to another color. It starts/reuses only the matching owned run.
  bbh skills/chromium-test/scripts/browser_provisioner.py request \
    <program> green --auth-domain videogp.superdrug.com --agent-id <agent-id> --run-id <run-id> \
    --purpose "owned IDOR comparison"

  # The provisioner registers the browser and renews identified task owners.
  # Declare a bounded manual wait, rather than releasing pending work:
  bbh skills/chromium-test/scripts/browser_provisioner.py touch --lease-id <lease-id> --agent-id <agent-id> \
    --work-state awaiting-input --awaiting-seconds 1800

  # Optional early terminal cleanup (automatic when the task supervisor exits):
  bbh skills/chromium-test/scripts/browser_provisioner.py release --lease-id <lease-id> --agent-id <agent-id> \
    --disposition completed --profile-health healthy
  ```

  Omit `--auth-domain` only when the inventory's `auth_host_filter` identifies
  the intended auth surface. Pass it explicitly when one account/color has
  independent auth state for multiple domains. A lock applies to that exact
  auth-domain/account pair; a pre-migration active lease without a domain is a
  conservative global lock until it is released.

  `browser_lease_enabled=no` and lifecycle `deleted`/`disabled`/`suspended` are
  never offered as account alternatives. Account writers use lifecycle `active`;
  legacy `live` records remain leasable during migration. `anon`, `anon1`, and
  `anon2` are the default durable anonymous slots, and an exact `anon<N>` slot
  may be requested without adding a fake account record. Record global principal
  tier as `admin` (the owner-equivalent) or `user`; anonymous browser slots are not
  accounts.
  Record program-specific organization access with
  `--organization-access ORG[:TIER[:PLAN]]`, and program-specific permission
  labels through repeatable `--capability`. These are shown so the caller can
  choose a compatible fixture rather than merely an unlocked color.

  A locked response may list **explicitly available alternatives**. An agent must
  select and acquire one of them itself; the script never switches identities.
  Use browser capture for stateful flows, then send bounded IDOR/BOLA replays
  through the task MITM lane using the deliberately selected account's approved
  auth seed/session bridge.
- **Verification:**

  ```bash
  uv run --python .venv/bin/python --with pytest python -m pytest agents/test_browser_profile_lease.py -q
  ```
- **Owner/scope:** Bug Bounty Harness / Chromium Test
- **Last verified:** 2026-09-10

## `browser_provisioner.py`

- **Purpose:** Node-local browser admission, profile/instance leasing,
  activity-aware ownership, verified cleanup and fenced live handoff.
- **Inputs:** Existing program/account selectors or `--task-owned`; agent/run,
  purpose, existing proxy/display settings; optional `--instance-key SLOT`,
  `--idle-seconds N` (claim window, default 900), `--owner-pid` (diagnostics and
  legacy lifecycle). Headless task mode does not require a PID; headed task
  mode does, because native input is untracked.
- **Outputs:** Safe receipts with `instance_id`, `pane_id`, `instance_key`,
  `account_color`, activity and watcher-health metadata. IDs remain stable
  across live handoff, differ for concurrent browsers and change on restart.
  This is **pane identity metadata, not an implemented pane UI**. Private launch
  records retain full generation-path CDP URLs.
- **Mutates:** Selected local lease/manager databases, profile paths, owned
  browser/display units and watcher. `BROWSER_PROVISIONER_STATE` isolates both
  databases. No new authentication retry or alternate-account selection.
- **Instances:** Keys use separate
  `<program>/web/browser-instances/<domain>/<account>/<slot>` trees. Omitted
  keys on ordinary request/start now select an automatic isolated slot: retry
  the same agent/run, otherwise claim an observable idle automatic slot through
  the existing atomic freeze, reuse a stopped automatic slot, or allocate a
  new slot. Private selection provenance excludes explicitly named slots even
  with an `auto-` prefix; an active transferee's slot is never selected merely
  because its key matches the original owner's hash. Canonical account
  single-browser policy still applies.
  Existing legacy manager/lease records or known on-disk legacy profile paths
  preserve legacy exclusivity, without copying or migrating session state.
  `--legacy-profile` explicitly retains that behavior for fresh selectors.
  Explicit keys and task-owned namespaces remain supported and are not
  automatically migrated. Unresolved account selectors do not opt into pooling.
- **Displays:** Under the same node start lock, auto/KasmVNC launch selects an
  unused X display and loopback web port, excluding running registered displays/
  ports, X sockets/locks and bound ports. Explicit occupied choices queue before
  lease acquisition. This serializes this manager's callers, not unrelated X
  server launchers. Same-owner incompatible headed/headless or strict-KasmVNC
  retries report `display-mode-mismatch` rather than silently returning a
  non-graphical browser. Existing Tailscale transport is unchanged.
- **Activity:** New headless pipe browsers track caller CDP work (navigation,
  input, evaluation and screenshots). Discovery/version checks, domain
  enablement, open sockets, events, live PID and watcher/touch heartbeats do not
  count. Arbitrary evaluation is counted as work, not semantically inspected.
  **Native headed input is untracked**: headed and older records retain
  conservative PID/explicit-release behavior pending a native-input integration.
  An explicitly supplied supervisor dying still triggers automatic cleanup;
  bounded operations and reservations win the atomic recheck first.
- **Idle claim:** The existing owner's 1–7199-second window controls claim
  eligibility. The adapter atomically freezes command admission only if no
  in-flight command, reservation or newer activity wins the recheck. Compatible
  fixed browser-owned proxy routes permit same-process generation-fenced headless reuse;
  task routes and non-revocable control retain verified restart fallback.
- **Cleanup:** Request/start checks tracked browsers unused for at least 7200
  seconds before admission. It verifies unit/root/CDP termination and retains
  the profile. `reap-idle` uses that same fixed stop threshold; its legacy
  `--idle-seconds` cannot lower it. Failed stop keeps the lease and reports an
  error. Control is restored only for a freshly verified healthy exact runtime;
  partial or unverifiable stops remain frozen pending explicit reconciliation.
- **Reservations:** `touch --work-state awaiting-input --awaiting-seconds N`
  grants an absolute 1–3600-second reservation; repetition cannot slide it.
  `touch --work-state active` cancels it but does not manufacture activity.
  Late waiting renewals are rejected.
- **Retention:** Existing 14-day manifest-only stopped-profile retention also
  handles instance trees. It never discovers arbitrary profile directories.
- **Verification:** `.venv/bin/python -m pytest agents/test_browser_resources.py agents/test_browser_provisioner.py agents/test_browser_profile_lease.py agents/test_browser_lease_recovery.py agents/test_browser_lifecycle.py -q`.
  Opt-in real fixtures: `BBH_LOCAL_BROWSER_SMOKE=1 .venv/bin/python -m pytest agents/test_browser_lifecycle_systemd.py agents/test_browser_lifecycle.py -q`.
- **Owner/scope:** Chromium Test scripts; Linux/user-systemd browser node.
  Native-input/pane integration remains a parent-owned follow-up. Local headed
  fixture coverage uses private Xvfb and CDP, not KasmVNC input telemetry. Do not
  infer native idleness or revocation from X event observation, display refresh,
  socket liveness or these passing tests. Headed idle eviction stays disabled.
- **Last verified:** 2026-09-21; loopback/about:blank fixtures only.
- **Generic example**, no account inventory:

  ```sh
  bbh skills/chromium-test/scripts/browser_provisioner.py request \
    --task-owned --headless --agent-id <agent> --run-id <run> \
    --purpose '<normal browser task>' --instance-key research \
    --proxy-server <existing-task-proxy> --mitm-ca-cert <existing-task-ca>
  ```

  The profile preserves task-specific ordinary site state, grants no program
  authorization and never silently transfers another task's proxy.

## `browser_control.py`

- **Purpose:** Per-browser CDP transport over Chromium's private debugging pipe;
  no raw Chromium debugging TCP listener. Generation rotation detaches sessions,
  closes old WebSockets, rejects old URLs, and acknowledges a protocol barrier.
- **Activity:** Private Unix activity/freeze/reservation operations serialize
  with command admission. Discovery and passive events do not reset idle time.
  Pipe backpressure is bounded to 60 seconds; an incomplete frame fails only
  the owned browser closed. Dispatch bounds include queuing and cancellation.
- **Inputs:** Internal `PipeBrowser` API from `chromium_test.py`;
  internal `pipe-exec` child adapter. Not an alternate browser launch interface.
- **Outputs:** Private generation-path CDP URL and a private Unix control socket.
  Supports version/list discovery and browser/page WebSockets, not every Chrome
  debugging UI/HTTP endpoint.
- **Mutates:** Only the owned process, its CDP sessions, and loopback/Unix sockets.
- **Verification:** The focused and opt-in fixture commands above.
- **Owner/scope:** Chromium Test transport, Linux; operational isolation between
  cooperating same-UID controllers, **not** protection against hostile processes
  that can read owner files or access the control socket.
- **Last verified:** 2026-09-20.

## `browser_lifecycle.py`

- **Purpose:** Shared process identity (PID/start ticks/boot/node), conservative
  liveness classification, serialized node mutations, and atomic private JSON.
- **Inputs:** Import-only helper for the provisioner; no public CLI.
- **Outputs:** Active/terminal/unknown identity evidence and local lock contexts.
- **Mutates:** Explicit state-lock files and selected owner-only JSON records;
  process discovery itself is read-only.
- **Verification:** `agents/test_browser_lease_recovery.py` and
  `agents/test_browser_lifecycle.py` in the commands above.
- **Owner/scope:** Chromium Test lifecycle; no remote PID inference or profile
  migration. Missing lifecycle evidence never proves task death.
- **Last verified:** 2026-09-20.

## `chromium_test.py`

- **Purpose:** Launch or reuse the isolated Chromium process selected by the
  browser provisioner.
- **Inputs:** Profile, CDP, proxy, certificate, display, and target URL controls.
- **Outputs:** Browser launch/status receipt with owned process and endpoint
  metadata.
- **Mutates:** The selected task-owned browser profile and processes.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_chromium_test_launcher.py -q`
- **Owner/scope:** Chromium Test skill.
- **Last verified:** 2026-09-10.

## `mitm_lane.py`

- **Purpose:** Create, inspect, and stop a task-owned local mitmproxy lane.
- **Inputs:** Lane identifier, local port/state root, and lifecycle subcommand.
- **Outputs:** JSON lane state and proxy endpoint metadata.
- **Mutates:** The selected local lane process and state directory for lifecycle
  operations.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_mitm_lane.py -q`
- **Owner/scope:** Chromium Test skill.
- **Last verified:** 2026-09-10.

## `hoster_mitm_lane.py`

- **Purpose:** Lease and manage one Hoster-backed mitmproxy lane through bounded
  SSH dispatch.
- **Inputs:** Lane/account identity, remote connection, port, and lifecycle
  controls.
- **Outputs:** Sanitized lane lease and status receipts.
- **Mutates:** The selected Hoster lane and local lease metadata for explicit
  lifecycle operations.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_hoster_mitm_lane.py -q`
- **Owner/scope:** Chromium Test skill.
- **Last verified:** 2026-09-10.

## `proxy_store.py`

- **Purpose:** Build and query a sanitized SQLite index of task MITM lane
  traffic.
- **Inputs:** Captured lane flows, query filters, and configured store path.
- **Outputs:** Sanitized indexed request metadata and query results.
- **Mutates:** The selected SQLite store for ingest/update operations; queries
  are read-only.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_proxy_store.py -q`
- **Owner/scope:** Chromium Test skill.
- **Last verified:** 2026-09-10.
- **Coverage:** Indexed fields and secret classifiers are non-exhaustive; absent
  records do not prove absent traffic.

## `mitm_chromium_profile.py`

- **Purpose:** Prepare one Chromium NSS profile to trust the selected mitmproxy
  CA certificate.
- **Inputs:** Profile directory, CA certificate path, and certificate label.
- **Outputs:** JSON certificate-import status.
- **Mutates:** Only the selected Chromium profile's NSS certificate database.
- **Verification:** `.venv/bin/python -m py_compile skills/chromium-test/scripts/mitm_chromium_profile.py`
- **Owner/scope:** Chromium Test skill.
- **Last verified:** 2026-09-10.

## `install.sh`

- **Purpose:** Install the `certutil` dependency through a supported system
  package manager when it is absent.
- **Inputs:** Host package-manager availability and explicit operator execution.
- **Outputs:** Installed `certutil` command or an actionable unsupported-manager
  error.
- **Mutates:** System packages and therefore requires explicit operator review;
  it is never an automatic script-maintenance step.
- **Verification:** `bash -n skills/chromium-test/scripts/install.sh`
- **Owner/scope:** Chromium Test skill / explicit dependency setup.
- **Last verified:** 2026-09-10.
