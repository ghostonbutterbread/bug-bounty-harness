# Chromium Test Scripts

## `kasmvnc_session.py`

- **Purpose:** Starts, checks, and stops one task-owned KasmVNC display for a
  headed Chromium manual handoff. The helper selects a free local HTTP port
  when requested with `--web-port` omitted and records only display/port
  metadata under the supplied state directory.
- **Security:** The KasmVNC endpoint is loopback-only (`127.0.0.1`) and uses
  HTTP. When remote access is required, publish that local port through a
  task-specific Tailscale **Serve** route, which terminates HTTPS; never use
  Funnel or a public/LAN listener. CDP remains loopback-only and is not
  published through KasmVNC.
- **Walkthrough:**

  ```bash
  KASM="$HARNESS_ROOT/skills/chromium-test/scripts/kasmvnc_session.py"
  python3 "$KASM" start --display 20 --web-port 8463 --json
  python3 "$KASM" status --display 20 --json
  python3 "$KASM" stop --display 20 --json
  ```

  The Chromium launcher owns the normal start path:

  ```bash
  python3 "$HARNESS_ROOT/skills/chromium-test/scripts/chromium_test.py" \
    <program> "manual handoff" --display-backend kasmvnc \
    --kasmvnc-display 20 --kasmvnc-web-port 8463 --json
  ```

  Its JSON result includes the loopback `kasmvnc.web_url` and an exact scoped
  `kasmvnc.stop_command`. The default display backend is unchanged; KasmVNC is
  used only with `--display-backend kasmvnc`.

## `browser_profile_lease.py`

- **Purpose:** Coordinates one persistent Chromium profile per `program/account`
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
  LEASE="$HARNESS_ROOT/skills/chromium-test/scripts/browser_profile_lease.py"

  # Ask by global principal tier; owner roles map to admin. Anonymous has no
  # account or persistent browser profile and should use an ephemeral lane.
  python3 "$LEASE" status <program> --tier admin
  python3 "$LEASE" status <program> --tier anonymous

  # Ask first for a named profile. This reports role, program-specific org/plan
  # access, capabilities, lock state, and probes a registered local CDP endpoint.
  python3 "$LEASE" status <program> --account green

  # Acquire exactly the requested account; it never falls back to another color.
  python3 "$LEASE" acquire <program> green \
    --agent-id <agent-id> --run-id <run-id> --purpose "owned IDOR comparison"

  # Start or reuse Chromium through chromium_test.py with the resolved alias from
  # acquire output (`launch.account`), not necessarily the requested color.
  # Use the persistent default profile; do not pass --ephemeral-profile.
  python3 "$HARNESS_ROOT/skills/chromium-test/scripts/chromium_test.py" \
    <program> "owned IDOR comparison" --account <launch.account> --run-id <run-id> --json

  # Once the recorded browser is ready on the profile host, bind its loopback CDP.
  python3 "$LEASE" register-browser \
    --lease-id <lease-id> --agent-id <agent-id> \
    --cdp-url http://127.0.0.1:<port> --service-unit <unit>

  # A question/blocker is not terminal: retain and renew the lease instead.
  python3 "$LEASE" renew --lease-id <lease-id> --agent-id <agent-id> \
    --work-state awaiting-input

  # Release only after a terminal outcome, recording whether the next agent may
  # safely reuse the persistent profile.
  python3 "$LEASE" release --lease-id <lease-id> --agent-id <agent-id> \
    --disposition completed --profile-health healthy
  ```

  `browser_lease_enabled=no` and lifecycle `deleted`/`disabled`/`suspended` are
  never offered as alternatives. Record global principal tier as `admin` (the
  owner-equivalent) or `user`; `anonymous` is virtual and has no account record.
  Record program-specific organization access with
  `--organization-access ORG[:TIER[:PLAN]]`, and program-specific permission
  labels through repeatable `--capability`. These are shown so the caller can
  choose a compatible fixture rather than merely an unlocked color.

  A locked response may list **explicitly available alternatives**. An agent must
  select and acquire one of them itself; the script never switches identities.
  Use browser capture for stateful flows, then send bounded IDOR/BOLA replays
  through the task MITM lane using the deliberately selected account's approved
  auth seed/session bridge.
- **Tests:**

  ```bash
  python3 -m pytest agents/test_browser_profile_lease.py -q
  ```
- **Owner:** Bug Bounty Harness / Chromium Test
- **Last verified:** 2026-07-28
