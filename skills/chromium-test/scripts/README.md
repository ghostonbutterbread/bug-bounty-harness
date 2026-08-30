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
  bbh skills/chromium-test/scripts/browser_profile_lease.py status <program> --account green

  # Request exactly the selected account; the provisioner leases it and never
  # falls back to another color. It starts/reuses only the matching owned run.
  bbh skills/chromium-test/scripts/browser_provisioner.py request \
    <program> green --agent-id <agent-id> --run-id <run-id> \
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
- **Tests:**

  ```bash
  python3 -m pytest agents/test_browser_profile_lease.py -q
  ```
- **Owner:** Bug Bounty Harness / Chromium Test
- **Last verified:** 2026-07-28
