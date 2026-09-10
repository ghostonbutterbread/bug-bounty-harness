# Chromium Test Scripts

## Inventory

- `browser_provisioner.py` — canonical admission, profile-lease, and Chromium
  request path.
- `chromium_test.py` — isolated Chromium launcher used by the provisioner.
- `browser_profile_lease.py` — exclusive owned-account/profile lease registry.
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

  # Once the recorded browser is ready on the profile host, bind its loopback CDP.
  bbh skills/chromium-test/scripts/browser_profile_lease.py register-browser \
    --lease-id <lease-id> --agent-id <agent-id> \
    --cdp-url http://127.0.0.1:<port> --service-unit <unit>

  # A question/blocker is not terminal: retain and renew the lease instead.
  bbh skills/chromium-test/scripts/browser_profile_lease.py renew --lease-id <lease-id> --agent-id <agent-id> \
    --work-state awaiting-input

  # Release only after a terminal outcome, recording whether the next agent may
  # safely reuse the persistent profile.
  bbh skills/chromium-test/scripts/browser_profile_lease.py release --lease-id <lease-id> --agent-id <agent-id> \
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

- **Purpose:** Provide the canonical admission, exact-profile lease, and
  launch/reuse path for engagement Chromium sessions.
- **Inputs:** Program, account/profile, agent/run identifiers, purpose, URL, and
  approved browser/proxy controls.
- **Outputs:** JSON admission and browser lifecycle receipts.
- **Mutates:** Task-owned profile leases and browser/display processes only
  after admission; dry-run remains non-launching.
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_browser_provisioner.py -q`
- **Owner/scope:** Chromium Test skill.
- **Last verified:** 2026-09-10.

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
