---
name: mullvad
description: "Select and rotate West Coast Mullvad exit nodes through Tailscale for scoped bug bounty connectivity and network-path recovery."
---

# Mullvad via Tailscale Exit Nodes

Use Tailscale's Mullvad add-on as the VPN path. Select and rotate Mullvad exit nodes with `tailscale`, **not** the standalone Mullvad CLI's relay commands. Read `prompts/mullvad-playbook.md` from the BBH repository for migration, verification, and recovery details.

Do not rotate to evade target rules, rate limits, account bans, WAF enforcement, or explicit blocking after noisy testing. Pause target traffic while changing routes. Keep exits in the US West Coast (WA, OR, CA) by default; if none works, ask Ryushe before leaving that region.

## Discover and select

```bash
tailscale status
tailscale get exit-node
tailscale exit-node list --filter=USA   # current available hosts; inspect city
tailscale set --exit-node=us-sea-wg-001.mullvad.ts.net
```

The hostname is an **example**, not a fixed relay: choose a currently listed Seattle, Oregon (if offered), Los Angeles, San Jose, or San Francisco Mullvad host. The list shows Tailscale-internal `100.x` addresses, **not** the public exit IP. The command is `tailscale set --exit-node=...`, not `tailscale --exit-node=...`. An existing standalone Mullvad VPN tunnel can interfere; follow the playbook's migration preflight before switching VPN managers.

For a rotation, choose a *different* currently listed host in the same West Coast city or another West Coast city and run `tailscale set --exit-node=<listed-mullvad-hostname>` again. Do not use `auto:any` when region control matters: an automatically suggested exit can be outside the West Coast or a non-Mullvad exit.

## Verify every selection before resuming

```bash
tailscale get exit-node
curl -4fsS --max-time 10 https://ip.me
curl -4fsS --max-time 10 https://am.i.mullvad.net/json
```

The selected hostname must match the intended node. Confirm the public IPv4 is **not** the normal ISP address and Mullvad's response reports `mullvad_exit_ip: true`; compare before/after public IPs when rotating. A `100.x` Tailscale address or a selected-node setting alone is not proof that internet traffic uses the VPN. If routing or verification fails, stop target traffic and recover using the playbook; do not test on an unverified ISP path. If IPv6 is relevant, check it separately for leaks.

For a scoped connectivity problem, preserve the exact symptom, then verify DNS and a low-noise request after the new exit. Record the previous and new host, public IPs, command, verification, and whether the original symptom recovered. Stop and ask if the target forbids VPNs, the issue is an account/application ban, the workflow is state-changing, or three changes fail to restore connectivity.
