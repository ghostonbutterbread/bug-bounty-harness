---
name: mullvad
description: "Prefer West Coast Mullvad exit nodes through Tailscale; use standalone Mullvad CLI when Tailscale exits are unavailable or not allowed."
---

# Mullvad Egress: Tailscale First, Standalone Fallback

Use this skill for VPN setup, West Coast exit selection/rotation, or scoped network-path recovery. Read the BBH repository's `prompts/mullvad-playbook.md` before a one-time manager handoff or fallback. Changing the exit does **not** authorize evading target rules, rate limits, account bans, WAF enforcement, or explicit VPN blocking.

## Choose one VPN manager per host

1. Check `tailscale status`, `tailscale get exit-node`, and `tailscale exit-node list --filter=USA`. If the host is connected to its tailnet, authorized for the Mullvad add-on, and a US West Coast Mullvad node is listed, **prefer Tailscale**. A Tailscale connection alone does not route public internet traffic through Mullvad; the selected exit node does.
2. If Tailscale is not installed, not connected, not permitted for Mullvad on this host, or has no usable West Coast exit, **use the standalone Mullvad CLI** once any prior exit selection is known to be clear. Do not disconnect a working standalone tunnel merely to discover that the Tailscale exit is unavailable.
3. Keep one active egress owner: on a planned Tailscale handoff, inspect the standalone tunnel, daemon auto-connect (`mullvad auto-connect get`), **independent GUI Auto-connect** (if the app is present), and lockdown setting. Pause target traffic and check active workloads/recovery access; turn **off both standalone Mullvad auto-connect paths** before `mullvad disconnect --wait` and selection of the Tailscale Mullvad exit. If a GUI auto-connect path is present but cannot be disabled and verified, do not claim a persistent handoff. Ryushe approves the mode-specific auto-connect rule, not silent changes to lockdown or disruption of active workloads. For CLI fallback, clear and verify any selected Tailscale exit **before** reconnecting Mullvad, then set `mullvad auto-connect set on` and verify it; if Tailscale is inaccessible and a prior selection cannot be ruled out, stop for recovery rather than assuming it is clear. A transition can briefly expose ISP egress or interrupt remote access.

Stay in US West Coast cities (WA, OR, CA); inspect the **live** exit list or Mullvad relay list rather than relying on a fixed hostname. Ask Ryushe before leaving that region. Do not use `auto:any`: it need not choose a West Coast Mullvad exit.

Before a remote handoff, read the playbook's preflight gate: verify `tailscale set` privilege, independent console/LAN control, a safe window and workload-specific checks; capture route, policy rules, DNS, egress and both managers' settings. Exit-node LAN access can preserve remote SSH while permitting LAN DNS outside the VPN, so decide and verify that tradeoff explicitly. Do not infer a completed disconnect from a hung Mullvad command or public DNS health from direct-IP HTTPS.

## Startup follows the selected manager

- **Tailscale-managed Mullvad:** On systemd Linux, check `systemctl is-enabled tailscaled` and `systemctl is-active tailscaled`; if not enabled, inspect the existing service owner before deliberately enabling the installed `tailscaled` service. The Tailscale client must already be authenticated/online, a **specific listed West Coast Mullvad exit** selected, and `tailscale get exit-node` must show that selection. Set `mullvad auto-connect set off`, read it back, and ensure independent GUI Auto-connect (if present) is **off**; leave its daemon available for later fallback, but disconnected. A one-time `tailscale up` or merely active tailnet state is not a startup guarantee. On another OS, check its own Tailscale startup manager.
- **Standalone-managed Mullvad:** Leave Tailscale connected for peer traffic if useful, but clear/read back its exit selection; set `mullvad auto-connect set on` and check `mullvad auto-connect get`. Inspect independent GUI Auto-connect if installed; keep it consistent with the selected manager. Check `mullvad status -v` for the actually connected West Coast relay.
- **After boot/restart:** Check service/startup state, selected exit or connected relay, and public egress **on the host/path doing the work** before scoped traffic resumes. Enabled startup plus a saved exit preference does not prove the relay is reachable or prevent ISP traffic during boot/failure. If checks fail, stop target traffic and recover a verified VPN path; do not silently proceed over the ISP. Do not reboot an active host merely to test this rule.

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

If already connected via the CLI, rotate to a different listed West Coast city/relay with `mullvad relay set location ... && mullvad reconnect --wait`. Verify the CLI is connected and `mullvad status -v` shows an **actual connected relay/location in WA, OR, or CA** matching the selection, Tailscale has **no** selected exit (when available to inspect), the public IP is not the ISP's, and Mullvad reports `mullvad_exit_ip: true`. After a failed Tailscale migration that returns to standalone Mullvad, set daemon auto-connect **on** and verify it; restore any GUI preference only if consistent with standalone mode. Do not leave the standalone fallback with auto-connect off merely because it was off before the attempt.

Verify on the actual egress host/path (account for proxies, and check IPv6 when relevant). If checks fail, stop target traffic, restore a verified VPN path, and do not silently use ISP egress. For scoped failures, record the prior/new manager, relay, public IP, symptom, command and retest. Stop and ask if the target forbids VPNs, the issue is an account/application ban, state-changing work is at risk, or three exit changes fail.

The fallback is an **explicit, verified manager switch**, not tested automatic failover or a kill switch. Check `ip -4 rule`, `ip -4 route get 1.1.1.1`, `resolvectl status`, public hostname resolution, IPv6 where present, and independent SSH plus affected workloads after a handoff; a selected exit, peer ping or host curl alone is not enough. Ghost requires Tailscale operator privilege; Hoster's failed Mullvad disconnect/public DNS and active workloads must be resolved before live migration (2026-10-08 snapshot; recheck). Review any LAN-versus-DNS privacy policy, fail-closed/automatic fallback design, and failure-injection evidence separately before claiming either property.
