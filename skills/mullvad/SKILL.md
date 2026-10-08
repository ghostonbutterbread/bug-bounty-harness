---
name: mullvad
description: "Prefer West Coast Mullvad exit nodes through Tailscale; use standalone Mullvad CLI when Tailscale exits are unavailable or not allowed."
---

# Mullvad Egress: Tailscale First, Standalone Fallback

Use this skill for VPN setup, West Coast exit selection/rotation, or scoped network-path recovery. Read the BBH repository's `prompts/mullvad-playbook.md` before a one-time manager handoff or fallback. Changing the exit does **not** authorize evading target rules, rate limits, account bans, WAF enforcement, or explicit VPN blocking.

## Choose one VPN manager per host

1. Check `tailscale status`, `tailscale get exit-node`, and `tailscale exit-node list --filter=USA`. If the host is connected to its tailnet, authorized for the Mullvad add-on, and a US West Coast Mullvad node is listed, **prefer Tailscale**. A Tailscale connection alone does not route public internet traffic through Mullvad; the selected exit node does.
2. If Tailscale is not installed, not connected, not permitted for Mullvad on this host, or has no usable West Coast exit, **use the standalone Mullvad CLI** once any prior exit selection is known to be clear. Do not disconnect a working standalone tunnel merely to discover that the Tailscale exit is unavailable.
3. Keep one active egress owner: on a planned Tailscale handoff, inspect the standalone tunnel, daemon auto-connect (`mullvad auto-connect get`), **independent GUI Auto-connect** (if the app is present), and lockdown setting. Pause target traffic; agree with Ryushe before changing either auto-connect preference or a privacy control, then disconnect the standalone VPN with `mullvad disconnect --wait` and select the Tailscale Mullvad exit. If using the CLI fallback, clear and verify any selected Tailscale exit **before** reconnecting Mullvad; if Tailscale is inaccessible and a prior selection cannot be ruled out, stop for recovery rather than assuming it is clear. A transition can briefly expose ISP egress or interrupt remote access; obtain a safe recovery path and check active workloads first.

Stay in US West Coast cities (WA, OR, CA); inspect the **live** exit list or Mullvad relay list rather than relying on a fixed hostname. Ask Ryushe before leaving that region. Do not use `auto:any`: it need not choose a West Coast Mullvad exit.

## Tailscale path (preferred)

```bash
tailscale exit-node list --filter=USA
tailscale set --exit-node=us-sea-wg-001.mullvad.ts.net  # example; select a listed host
mullvad status
tailscale get exit-node
curl -4fsS --max-time 10 https://ip.me
curl -4fsS --max-time 10 https://am.i.mullvad.net/json
```

After the handoff, the standalone tunnel must say **Disconnected**; the chosen Tailscale node must match a listed Mullvad host; the public IP must not be the ordinary ISP IP; and Mullvad's JSON must report `mullvad_exit_ip: true` with `mullvad_exit_ip_hostname` matching that host's short relay name. Rotation repeats `tailscale set --exit-node=<different-listed-west-coast-host>` and the checks, **not** the standalone disconnect. The node's `100.x` tailnet IP is not its public exit IP. Select by the exact name shown in `tailscale exit-node list` or by its listed tailnet IP if the name is not accepted.

## Standalone Mullvad path (fallback)

```bash
mullvad relay list             # discover current West Coast relays
mullvad relay set location us sea  # example: listed Seattle city
mullvad connect --wait
mullvad status -v
curl -4fsS --max-time 10 https://ip.me
curl -4fsS --max-time 10 https://am.i.mullvad.net/json
```

If already connected via the CLI, rotate to a different listed West Coast city/relay with `mullvad relay set location ... && mullvad reconnect --wait`. Verify the CLI is connected and `mullvad status -v` shows an **actual connected relay/location in WA, OR, or CA** matching the selection, Tailscale has **no** selected exit (when available to inspect), the public IP is not the ISP's, and Mullvad reports `mullvad_exit_ip: true`. Preserve the host's prior auto-connect preference on a failed Tailscale migration; only retire it on a successful planned handoff.

Verify on the actual egress host/path (account for proxies, and check IPv6 when relevant). If checks fail, stop target traffic, restore a verified VPN path, and do not silently use ISP egress. For scoped failures, record the prior/new manager, relay, public IP, symptom, command and retest. Stop and ask if the target forbids VPNs, the issue is an account/application ban, state-changing work is at risk, or three exit changes fail.
