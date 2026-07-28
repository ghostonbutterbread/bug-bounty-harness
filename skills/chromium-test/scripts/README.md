# Chromium Test Scripts

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

  # Ask first. This reports account role/capabilities, lock state, and probes a
  # previously registered local CDP endpoint without disclosing it to non-owners.
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

  # Renew during a long owned workflow, then release after normal browser cleanup.
  python3 "$LEASE" renew --lease-id <lease-id> --agent-id <agent-id>
  python3 "$LEASE" release --lease-id <lease-id> --agent-id <agent-id>
  ```

  `browser_lease_enabled=no` and lifecycle `deleted`/`disabled`/`suspended` are
  never offered as alternatives. Populate each account's repeatable non-secret
  `capabilities` labels (for example `org-owner`, `org-member`, or
  `shared-org:<owned-resource>`) through `account_inventory.py`; these are shown
  so the caller can choose a compatible fixture rather than merely an unlocked
  color.

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
