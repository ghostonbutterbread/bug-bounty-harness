---
name: chromium-handoff
description: "Expose a safe manual handoff page for an existing CDP Chromium session through Tailscale Serve with an SSH tunnel fallback."
---

# Chromium Handoff

Use when a Chromium/CDP browser is stuck on CAPTCHA, Cloudflare, Turnstile,
bot-check, login step-up, or another page that Ryushe needs to complete
manually.

This skill does not launch the browser. Use `chromium-test` first, then attach
this handoff server to the existing CDP endpoint.

## Required Pairings

1. Load `proxy-routing-policy` first when proxy lane selection matters.
2. Use `chromium-test` to launch an isolated browser with CDP bound to
   `127.0.0.1`.
3. Use `hoster-ssh` for Hoster lifecycle commands; the handoff server must be
   owned by a task-scoped user-systemd unit, never an SSH cgroup.
4. Load `http-status-live-policy` or `waf-live-policy` when the stop condition
   is a 403, 429, Cloudflare page, CAPTCHA, or bot challenge.

## Transport Contract

- **Tailscale Serve is preferred.** It exposes only the local handoff UI to
  Ryushe's tailnet identity over HTTPS; it never exposes CDP.
- **SSH forwarding is the fallback.** Always include a ready-to-run SSH command
  in a handoff response, even when the Tailscale URL is available.
- Chrome CDP, browser profiles, proxy control, and the handoff server bind to
  `127.0.0.1` on Hoster. Do not bind CDP to a Tailscale or LAN address.
- Tailscale is a control/view transport only. It must not change the browser's
  existing proxy/effective egress IP.
- Use the fixed handoff UI port `9231`; each task's CDP port remains dynamic
  and loopback-only.

## One-time Hoster Prerequisites

The Hoster administrator must configure this once. Agents must only verify it,
not attempt interactive login, change tailnet membership, alter ACLs, or use
Funnel/public exposure:

```bash
sudo systemctl enable --now tailscaled
sudo tailscale set --operator=ryushe
systemctl is-enabled tailscaled
systemctl is-active tailscaled
tailscale status
tailscale serve status
```

`tailscaled` is expected to start after reboot and remain running. The actual
browser, handoff server, and Serve route remain on-demand. The tailnet must
allow Ryushe's identity/devices to reach Hoster HTTPS; do not broaden access or
assume an ACL change is authorized.

## Workflow

1. Confirm the target browser has a live CDP endpoint:
   ```bash
   curl --fail --silent http://127.0.0.1:<cdp_port>/json/list
   ```
2. Start the loopback-only handoff server through its task-owned supervisor:
   ```bash
   CDP_URL=http://127.0.0.1:<cdp_port> \
   LISTEN_HOST=127.0.0.1 \
   LISTEN_PORT=9231 \
   node "$HARNESS_ROOT/skills/chromium-handoff/scripts/cdp_handoff_server.js"
   ```
   Verify the local UI before publishing it:
   ```bash
   curl --fail --silent http://127.0.0.1:9231/ >/dev/null
   ```
3. Prefer Tailscale Serve. From Hoster, use the bounded helper:
   ```bash
   "$HARNESS_ROOT/skills/chromium-handoff/scripts/handoff_transport.sh" start
   "$HARNESS_ROOT/skills/chromium-handoff/scripts/handoff_transport.sh" status
   ```
   Give Ryushe the HTTPS URL shown by `tailscale serve status`.
4. Always give the SSH fallback. Run these **on Ryushe's workstation**, not
   Hoster:
   ```bash
   ssh -i ~/.ssh/hoster -fN -L 9997:127.0.0.1:9231 ryushe@hoster
   xdg-open http://127.0.0.1:9997/
   ```
   On macOS use `open` rather than `xdg-open`.
5. Pause automation until Ryushe says to continue.
6. On resume/end, first withdraw the Tailscale route, then stop the handoff
   service and task browser through their recorded owner. Verify the local CDP
   endpoint is closed before removing the matching disposable profile:
   ```bash
   "$HARNESS_ROOT/skills/chromium-handoff/scripts/handoff_transport.sh" stop
   ```

## Failure and Fallback

- If `tailscale status` is not healthy, `tailscale serve` is unavailable, the
  route is not reachable, or publishing fails, do not expose an alternate
  public/LAN endpoint. Report the failure and provide the SSH fallback above.
- If the local handoff UI health check fails, do not start Serve; diagnose the
  browser/CDP and handoff server first.
- Do not leave a permanent SSH tunnel or a Serve route after handoff end.

## What The Handoff Page Does

- Serves a small page from `127.0.0.1:9231`.
- Streams screenshots from the selected CDP page.
- Forwards Ryushe's clicks and typed text to the browser through Playwright/CDP.
- Keeps the browser's authenticated profile and proxy routing on Hoster.

## Guardrails

- Do not bind Chrome CDP to `0.0.0.0`, a LAN address, or a Tailscale address.
- Do not use Tailscale Funnel or any public reverse proxy for browser handoff.
- Do not print, store, or copy raw cookies, bearer tokens, API keys, or session
  material from the browser or proxy.
- Do not use CAPTCHA-solving services, IP rotation, or challenge-bypass loops.
- Do not perform state-changing actions after handoff unless Ryushe explicitly
  approves the exact action.
- Stop and ask if the page would require purchases, billing changes, invites,
  messages, account deletion, or mutation of non-owned data.

## Notes

Raw DevTools forwarding is still useful for debugging, but it is awkward for
manual CAPTCHA solving. This handoff server is preferred when Ryushe needs a
simple remote browser view with click/type controls.
