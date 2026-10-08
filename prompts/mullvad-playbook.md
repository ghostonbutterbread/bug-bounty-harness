# Mullvad egress: Tailscale first, standalone fallback

## How the traffic flows

```text
Preferred (host has Tailscale Mullvad access):
Agent/browser -> host Tailscale client -> selected West Coast
Mullvad exit node -> public internet (Mullvad public IP)

Fallback (Tailscale exit unavailable/not allowed on host):
Agent/browser -> host standalone Mullvad tunnel -> selected
West Coast Mullvad relay -> public internet (Mullvad public IP)

Tailscale online WITHOUT a selected exit node:
Tailnet peer traffic uses Tailscale; ordinary internet traffic
uses the host's other default route. This is NOT VPN egress proof.
```

The Mullvad app and the Tailscale Mullvad add-on are alternative VPN managers on each host. Keep the tailnet connected, but use one **verified** Mullvad internet-egress path at a time. The exit node routes internet-bound traffic through Mullvad; the `100.x` tailnet address shown by Tailscale is not the public egress address. On Linux, `tailscale set --exit-node=<listed-hostname-or-tailnet-IP>` selects the exit. Hostname selection requires MagicDNS; use its listed Tailscale IP otherwise.

## Choose the path on each host

1. Inspect `tailscale status`, `tailscale get exit-node`, `tailscale exit-node list --filter=USA`, `mullvad status`, `mullvad auto-connect get`, and `mullvad lockdown-mode get`. Tailscale must be running, the device authorized for the Mullvad add-on, and a listed WA/OR/CA Mullvad exit available to prefer it. Do not choose a normal tailnet exit, `auto:any`, or an out-of-region node as a silent substitute.
2. If Tailscale is missing, inaccessible, unauthorized, or has no usable West Coast Mullvad exit, keep/use the **standalone Mullvad CLI**. Do not disconnect a working standalone VPN while just checking capabilities. If neither path works, stop target traffic rather than using the ISP route.
3. On a host with running agents/browsers/proxies, or one reached remotely, assess disruption and arrange a recovery path before changing its network. The operator's belief that no agents are active is not a substitute for checking. A VPN handoff can affect network sessions; do not kill agents or services as a shortcut.

## One-time move from standalone Mullvad to Tailscale

1. Record the current Mullvad relay/public IP, auto-connect and lockdown settings; confirm the desired **listed** West Coast Tailscale Mullvad exit and control/recovery path. Mullvad's "block connections without VPN" setting can prevent switching; do not silently turn it off. Pause target traffic.
2. If the standalone auto-connect is on, deliberately set it off with `mullvad auto-connect set off` for this migration (record the previous value for rollback). Then run `mullvad disconnect` followed promptly by `tailscale set --exit-node=<listed-west-coast-mullvad-hostname>`; no repeated standalone disconnect on subsequent Tailscale rotations. Disconnection can briefly expose ISP egress or interrupt remote control: do not do it unattended on a host that depends on the existing route.
3. Run the Tailscale verification below *before* resuming work. A selected exit alone is not proof; if the check fails, stop traffic, clear the selected Tailscale exit (`tailscale set --exit-node=`), reconnect standalone Mullvad (`mullvad connect --wait`), restore the prior auto-connect preference, and verify Mullvad egress. Do not claim Tailscale activation if rollback happened.

## Tailscale rotation (preferred once migrated)

```bash
tailscale exit-node list --filter=USA
tailscale set --exit-node=us-sea-wg-001.mullvad.ts.net   # example; choose live WA/OR/CA entry
mullvad status
tailscale get exit-node
curl -4fsS --max-time 10 https://ip.me
curl -4fsS --max-time 10 https://am.i.mullvad.net/json
```

Select a *different* listed host within Seattle, an available Oregon city, Los Angeles, San Jose or San Francisco for a rotation. Check standalone `mullvad status` is disconnected; selected Tailscale host matches the intended exit; the observed public IP is not the normal ISP IP; and the JSON reports `mullvad_exit_ip: true` plus `mullvad_exit_ip_hostname` matching the chosen host's short name. Compare previous/new public IPs rather than assuming they change. If IPv6 is relevant, test `curl -6fsS --max-time 10 https://ip.me`. If an HTTP proxy is in use, verify the egress from the machine/path carrying the target traffic, not an unrelated local proxy.

## Standalone CLI fallback / rotation

If Tailscale is installed and an exit had been selected, first clear it with `tailscale set --exit-node=`. Do not stop the tailnet. When Tailscale is absent or has no exit selection, skip this step.

```bash
mullvad relay list
mullvad relay set location us sea  # example; choose a listed WA/OR/CA relay
mullvad connect --wait
mullvad status
curl -4fsS --max-time 10 https://ip.me
curl -4fsS --max-time 10 https://am.i.mullvad.net/json
```

If already connected, use `mullvad relay set location <listed-west-coast-location> && mullvad reconnect --wait` for a new city/relay. Verify `mullvad status` connected, no Tailscale exit selected (when Tailscale is installed), and the public IP/Mullvad JSON confirm the VPN. Restore the previously recorded auto-connect preference if this fallback is recovering a failed migration.

## Scoped connectivity recovery

Preserve the exact DNS, browser, or proxy symptom. After two or three normal retries, distinguish a VPN path problem from local proxy/DNS configuration, then change one exit and verify. Retest one low-noise in-scope request (`getent hosts <host>` and a suitable `curl -I --max-time 15 https://<in-scope-host>/` or one browser reload). If still failing, record the result rather than cycling indefinitely.

Record previous/new manager and relay, city, public IP, exact symptom, command, verification, scoped retest and next action. Never rotate to evade target rules, rate limits, account bans, WAF enforcement, or explicit anti-VPN restrictions. Ask Ryushe before leaving the US West Coast, risking state-changing work, or after three failed changes. Never paste cookies, tokens or private URLs into chat.
