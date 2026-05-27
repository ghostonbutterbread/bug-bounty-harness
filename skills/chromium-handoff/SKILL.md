---
name: chromium-handoff
description: "Expose a safe manual handoff page for an existing CDP Chromium session so Ryushe can solve CAPTCHA, Cloudflare, Turnstile, bot challenges, or inspect a stuck browser through an SSH tunnel."
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
3. Load `http-status-live-policy` or `waf-live-policy` when the stop condition
   is a 403, 429, Cloudflare page, CAPTCHA, or bot challenge.

## Workflow

1. Confirm the target browser has a live CDP endpoint:
   ```bash
   curl -sS http://127.0.0.1:<cdp_port>/json/list
   ```
2. Start the handoff server on Hoster:
   ```bash
   CDP_URL=http://127.0.0.1:<cdp_port> \
   LISTEN_HOST=127.0.0.1 \
   LISTEN_PORT=9230 \
   node "$HARNESS_ROOT/skills/chromium-handoff/scripts/cdp_handoff_server.js"
   ```
3. Give Ryushe a local SSH tunnel command. Preferred local port is `9998`:
   ```bash
   ssh -i ~/.ssh/hoster -fN -L 9998:127.0.0.1:9230 ryushe@hoster
   xdg-open http://127.0.0.1:9998/
   ```
4. Pause automation until Ryushe says to continue.
5. After Ryushe solves or inspects the page, resume the same CDP browser
   session with Playwright or another CDP client.

## What The Handoff Page Does

- Serves a small page from `127.0.0.1:<listen_port>`.
- Streams screenshots from the selected CDP page.
- Forwards Ryushe's clicks and typed text to the browser through Playwright/CDP.
- Keeps the browser's authenticated profile and proxy routing on Hoster.

## Guardrails

- Do not bind Chrome CDP to `0.0.0.0` unless Ryushe explicitly asks.
- Do not expose the handoff server on public interfaces; use SSH tunneling.
- Do not use CAPTCHA-solving services, IP rotation, or challenge-bypass loops.
- Do not print, store, or copy raw cookies, bearer tokens, API keys, or session
  material from the browser or proxy.
- Do not perform state-changing actions after handoff unless Ryushe explicitly
  approves the exact action.
- Stop and ask if the page would require purchases, billing changes, invites,
  messages, account deletion, or mutation of non-owned data.

## Notes

Raw DevTools forwarding is still useful for debugging, but it is awkward for
manual CAPTCHA solving. This handoff server is preferred when Ryushe needs a
simple remote browser view with click/type controls.
