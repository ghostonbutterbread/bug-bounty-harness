# Chromium Handoff Scripts

## `cdp_handoff_server.js`

- **Purpose:** Serve a loopback-only screenshot/control handoff UI for one
  receipt-verified Chromium CDP session.
- **Inputs:** Browser launch receipt and loopback CDP/listener environment.
- **Outputs:** A bounded local HTTP handoff UI.
- **Mutates:** The selected browser page through explicit UI actions; it does not
  publish CDP directly.
- **Example:** `bbh skills/chromium-handoff/scripts/cdp_handoff_server.js`
- **Verification:** `python3 -m pytest agents/test_cdp_handoff_receipt.py -q`

## `handoff_transport.sh`

- **Purpose:** Publish or remove one loopback handoff UI through private
  Tailscale Serve routing.
- **Inputs:** `start`, `status`, or `stop` plus task-owned handoff ports.
- **Outputs:** Tailscale Serve status.
- **Mutates:** The selected private Serve route for `start` and `stop`; never
  publishes Chrome CDP or uses Funnel.
- **Example:** `bbh skills/chromium-handoff/scripts/handoff_transport.sh --help`
- **Verification:** `bbh skills/chromium-handoff/scripts/handoff_transport.sh --help`

These helpers expose only the selected live handoff. They do not enumerate or
prove the state of other browser sessions.
