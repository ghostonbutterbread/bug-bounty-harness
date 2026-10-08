# Mullvad via Tailscale: exit-node playbook

## Goal and boundary

Manage the Mullvad VPN add-on through Tailscale for West Coast exit selection and rotation. This is network-path management, not permission to evade target rules, rate limits, bans, explicit anti-VPN policy, or WAF enforcement after noisy testing. Pause target traffic while routing changes and resume only after the new public egress is verified.

## One-time migration from the standalone Mullvad app

1. On **each host** that will use an exit, confirm Tailscale is connected, the Mullvad add-on is enabled for that device, and a desired West Coast Mullvad node appears in `tailscale exit-node list --filter=USA`. `tailscale status` alone means tailnet connectivity, **not** VPN egress.
2. Check `mullvad status`, `mullvad lockdown-mode get`, and `mullvad auto-connect get`; record the current settings. If the standalone app is connected, arrange a safe operator/console recovery path first: disconnecting its tunnel can briefly expose normal ISP egress or interrupt the remote session. Mullvad's "block connections without VPN" setting can prevent the migration; don't silently turn a privacy control off. If auto-connect is on, agree with Ryushe to turn it off for a persistent migration (`mullvad auto-connect set off`), so the old tunnel does not reclaim routing after restart. Do not silently change either setting.
3. Stop target traffic. For the planned handoff, run `mullvad disconnect`, then immediately `tailscale set --exit-node=<listed-west-coast-mullvad-hostname>` on that host. This is a **one-time handoff**, not a step in each later rotation. Do not routinely stop Tailscale or use standalone Mullvad relay commands.
4. Run all verification below before resuming. If Tailscale cannot establish a verified exit, keep target traffic stopped; with operator access, clear a failed Tailscale exit selection if necessary (`tailscale set --exit-node=`), reconnect the standalone VPN (`mullvad connect --wait`), verify its public exit, and restore the recorded auto-connect preference if it was changed. Never silently continue over an ISP route.

Do not execute this initial disconnection unattended on a host whose control plane depends on the current VPN. When Tailscale is not connected or no authorized Mullvad node appears, resolve the device/add-on prerequisite first rather than selecting an arbitrary regular exit.

## Select or rotate (after migration)

```bash
tailscale get exit-node
tailscale exit-node list --filter=USA
tailscale set --exit-node=us-sea-wg-001.mullvad.ts.net   # example; choose from the live list
```

`tailscale exit-node list` also works; `--filter=USA` expands the country listing. Inspect the city column. Prefer Seattle, an Oregon city if listed, Los Angeles, San Jose, or San Francisco; rotate to another listed host in the same city or between those cities. Oregon is not guaranteed to be available. The `100.x` column is the node's tailnet IP, not its public Mullvad exit IP; use the hostname when MagicDNS is enabled, otherwise its listed tailnet IP. Avoid `auto:any` because it need not honor the West Coast or Mullvad restriction. Ask Ryushe before choosing a non-West-Coast fallback.

For a connectivity blocker: capture the exact symptom; retry a normal request two or three times; distinguish DNS/proxy/browser issues from VPN routing; then change one host and verify. Do not cycle exits during active payload testing.

## Verify after every selection

```bash
mullvad status
tailscale get exit-node
curl -4fsS --max-time 10 https://ip.me
curl -4fsS --max-time 10 https://am.i.mullvad.net/json
```

Confirm `mullvad status` shows the standalone VPN disconnected after migration, the selected Tailscale node is the intended Mullvad host, and the observed public IPv4 differs from the normal ISP address. Mullvad's JSON must report `mullvad_exit_ip: true` **and** `mullvad_exit_ip_hostname` matching the selected host's short relay name (for example `us-sea-wg-001`). Record public IPs before and after rotation; a host change need not guarantee a new public IP, so **check** rather than assume. A selected-node preference or Mullvad IP check alone cannot prove Tailscale routing while the standalone VPN is connected. If a proxy is configured, ensure the checks measure the actual egress host/path used by target traffic; check IPv6 separately (`curl -6fsS --max-time 10 https://ip.me`) when applicable. If verification fails, stop rather than testing from an unverified route.

For a scoped failure, check `getent hosts <host>` and one low-noise `curl -I --max-time 15 https://<in-scope-host>/` or one browser reload. If the original request is retry-safe, retry it once; if still blocked, record that rotation did not fix it rather than cycling indefinitely. Do not paste cookies, tokens, or private URLs into chat.

## Evidence / stop

Record previous node and public IP, exact symptom, chosen city/host and command, new selected node and public IP/Mullvad check, scoped retest, and next action. Stop and ask Ryushe if the target forbids VPNs, the issue appears to be an account/application ban, the workflow is state-changing, or three changes fail to restore connectivity.
