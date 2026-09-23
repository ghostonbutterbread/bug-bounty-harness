# Chromium Handoff Scripts

## `cdp_handoff_server.js`

- **Purpose:** Serve a loopback-only screenshot/control handoff UI for one
  receipt-verified Chromium CDP session.
- **Inputs:** Browser launch receipt and loopback CDP/listener environment.
- **Outputs:** A bounded local HTTP handoff UI.
- **Mutates:** The selected browser page through explicit UI actions; it does not
  publish CDP directly.
- **Example:** `bbh skills/chromium-handoff/scripts/cdp_handoff_server.js`
- **Verification:** `uv run --python .venv/bin/python --with pytest python -m pytest agents/test_cdp_handoff_receipt.py -q`
- **Owner/scope:** Chromium Handoff skill.
- **Last verified:** 2026-09-21 (deterministic consumer tests; see coverage below).

### Exact receipt and pane contract

Set `BROWSER_LAUNCH_RECEIPT` to the provisioner's **current private launch
record**, and `CDP_URL` to its exact `cdp_url`, including the generation path.
The safe manager status summary is not a launch record. The receipt is read
once: the UI never follows later record rewrites or adopts another generation.

Existing KasmVNC `display_fallback.reason`, imported/trusted certificate, live
owned PID/profile, exact endpoint equality and loopback requirements remain
mandatory. Ordinary UI use does not waive these gates. `LISTEN_HOST` is now
explicitly restricted to `127.0.0.1` before any browser connection or listener.

- Raw-port legacy receipts retain their live command-line checks.
- `control_mode: pipe-fenced` requires the actual pipe flag (not a raw debug
  port), matching Linux PID/start tick/boot/node identity, profile, stable UUID
  `instance_id == pane_id`, and a private owned Unix `control_socket`.
- A bounded, passive `GET /identity` on that private adapter socket must match
  the receipt process and exact generation URL and report available control.
  This needs the updated `browser_control.py`; older adapters without this
  endpoint fail closed and must be explicitly restarted by their owner.
- The server selects only one existing non-extension page. Multiple candidates,
  no candidates, or an absent intended target fail startup. Use
  `HANDOFF_PAGE_ID=<CDP target id>` to select an exact existing page; URLs and
  account colors are not selectors. It does not create a context/tab or choose a
  replacement when the selected page closes.
- Ready output and `GET /identity` expose only instance/pane/page IDs and mode
  (plus ready listener metadata), never profile, account, generation URL or
  page content. Legacy records without pane metadata show a legacy label.
- Loss of the exact process/control/page is terminal for this server: actions
  return 410 with a safe explanation; the UI disables controls and clears the
  image. Start a new handoff explicitly from a current receipt. It does not
  reconnect to another owner. Ordinary operation errors also fail closed.

The UI has **no automatic screenshot refresh**. Initial page loading and the
five-second identity poll do not issue screenshot/evaluation commands, renew
leases, or reserve idle time. Explicit refresh and post-action screenshots are
real requested CDP work and count as activity normally. The browser connection
may perform bounded setup work once; an unused open UI does not continuously
keep the browser alive. This intentionally trades live animation for truthful
idle accounting; no bridge activity bypass or fabricated heartbeat is added.

One server is one instance/page pane, not a multi-pane desktop registry. Route
publication remains a separate owner operation and was not exercised here.
Verification covers synthetic receipt/process/Playwright compatibility fixtures,
negative identity/control/selection cases, and the passive adapter identity
method. The existing opt-in real pipe/lifecycle fixtures were also rerun; a new
end-to-end real **handoff UI** smoke is still outstanding (tool approval pending
for its test addition). No real fallback/certificate-import verification is
claimed by the synthetic fixtures.

## `handoff_transport.sh`

- **Purpose:** Publish or remove one loopback handoff UI through private
  Tailscale Serve routing.
- **Inputs:** `start`, `status`, or `stop` plus task-owned handoff ports.
- **Outputs:** Tailscale Serve status.
- **Mutates:** The selected private Serve route for `start` and `stop`; never
  publishes Chrome CDP or uses Funnel.
- **Example:** `bbh skills/chromium-handoff/scripts/handoff_transport.sh --help`
- **Verification:** `scripts/bbh skills/chromium-handoff/scripts/handoff_transport.sh --help`
- **Owner/scope:** Chromium Handoff skill.
- **Last verified:** 2026-09-10.

These helpers expose only the selected live handoff. They do not enumerate or
prove the state of other browser sessions.
