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

The Mullvad app and the Tailscale Mullvad add-on are alternative VPN managers on each host. Keep the tailnet connected, but use one **verified** Mullvad internet-egress path at a time. The exit node routes internet-bound traffic through Mullvad; the `100.x` tailnet address shown by Tailscale is not the public egress address. On Linux, `tailscale set --exit-node=<listed-hostname-or-tailnet-IP>` selects the exit. Use the exact listed hostname; if it is not accepted, use that same node's listed Tailscale IP.

## Choose the path on each host

1. Inspect `tailscale status`, `tailscale get exit-node`, `tailscale exit-node list --filter=USA`, `mullvad status -v`, `mullvad auto-connect get`, and `mullvad lockdown-mode get`. If the Mullvad GUI/app is present, inspect its **separate GUI Auto-connect** setting too; the daemon CLI setting does not control it. On systemd Linux check `systemctl is-enabled tailscaled` and `systemctl is-active tailscaled` (on other systems, inspect the platform startup manager). Tailscale must be running, the device authorized for the Mullvad add-on, and a listed WA/OR/CA Mullvad exit available to prefer it. Do not choose a normal tailnet exit, `auto:any`, or an out-of-region node as a silent substitute.
2. If Tailscale is absent, unauthorized, or has no usable West Coast Mullvad exit, keep/use the **standalone Mullvad CLI** only after checking that no Tailscale exit is selected. Do not disconnect a working standalone VPN while just checking capabilities. If Tailscale is installed but its CLI/daemon is inaccessible and a previous selection cannot be inspected/cleared, stop target traffic and restore Tailscale inspection or obtain operator recovery; do not assume the old selection is gone. If neither path works, stop rather than using the ISP route.
3. On a host with running agents/browsers/proxies, or one reached remotely, assess disruption and arrange a recovery path before changing its network. The operator's belief that no agents are active is not a substitute for checking. A VPN handoff can affect network sessions; do not kill agents or services as a shortcut.

## One-time move from standalone Mullvad to Tailscale

1. Record the current Mullvad relay/public IP, **daemon and GUI Auto-connect** (where app is installed), and lockdown settings; confirm the desired **listed** West Coast Tailscale Mullvad exit and control/recovery path. Mullvad's "block connections without VPN" setting can prevent switching; do not silently turn it off. Pause target traffic.
2. Ryushe's mode-specific rule is: when Tailscale owns internet egress, **Mullvad auto-connect is off**; when standalone Mullvad owns it, daemon auto-connect is on. This does not authorize changing lockdown, restarting active services, or disrupting other agents. Verify Tailscale's existing service is enabled and active (after inspecting its owner if it must be enabled), and the client is authenticated. Turn off daemon auto-connect with `mullvad auto-connect set off` and read it back; separately turn off/read back GUI Auto-connect through its own UI if installed. If that GUI preference cannot be verified off, defer the persistent switch. Record prior settings for recovery. Then run `mullvad disconnect --wait` followed promptly by `tailscale set --exit-node=<listed-west-coast-mullvad-hostname>`; no repeated standalone disconnect on subsequent Tailscale rotations. Disconnection can briefly expose ISP egress or interrupt remote control: do not do it unattended on a host that depends on the existing route.
3. Run the Tailscale verification below *before* resuming work. A selected exit alone is not proof; if the check fails, stop traffic, clear the selected Tailscale exit (`tailscale set --exit-node=`) **and confirm it is clear** with `tailscale get exit-node`, set standalone daemon auto-connect **on** and read it back, reconnect Mullvad (`mullvad connect --wait`), and verify its West Coast egress. Restore other recorded GUI preferences only in a way consistent with the selected mode. If clearing/verifying the exit is impossible, stop for operator recovery rather than enabling a second ambiguous route. Do not claim Tailscale activation if rollback happened.

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

If Tailscale is installed and reachable, read `tailscale get exit-node`; if an exit is selected, clear it with `tailscale set --exit-node=` and **read back an empty selection** before connecting the standalone VPN. Keep the tailnet online. When Tailscale is absent and no selection could have been stored, skip this step. When Tailscale is installed but its CLI/daemon is inaccessible, do not guess that an old exit will stay inactive: stop target traffic and restore control of Tailscale or arrange operator recovery to clear/verify its selection before a fallback change.

For a persistent standalone mode, `mullvad auto-connect set on` and verify `mullvad auto-connect get` reports **on**. The GUI Auto-connect setting is independent: inspect it if installed and keep it consistent with the chosen manager; daemon auto-connect is the boot-time CLI setting. Do not disable `tailscaled` solely because the host uses standalone Mullvad—peer connectivity can remain active without an exit selection.

```bash
mullvad relay list
mullvad relay set location us sea  # example; choose a listed WA/OR/CA relay
mullvad connect --wait
mullvad status -v
curl -4fsS --max-time 10 https://ip.me
curl -4fsS --max-time 10 https://am.i.mullvad.net/json
```

If already connected, use `mullvad relay set location <listed-west-coast-location> && mullvad reconnect --wait` for a new city/relay. Verify `mullvad status -v` shows the **actual connected relay** and visible location in WA, OR, or CA matching the choice, no Tailscale exit is selected (when Tailscale is installed and inspectable), `mullvad auto-connect get` reports on, and the public IP/Mullvad JSON confirm the VPN.

## Boot/restart checks

The existing Tailscale client preference for a **specific** selected West Coast Mullvad exit is meant to survive a service restart; a running tailnet without a working selected exit is not Mullvad egress. Before enabling/starting a `tailscaled` service, check its existing system/user owners to avoid a competing manager. On systemd Linux, require enabled/active `tailscaled` for Tailscale mode; check `tailscale status`, `tailscale get exit-node`, and the actual public egress again after a scheduled boot/restart, before scoped work. For standalone mode, check daemon auto-connect on, the connected West Coast relay (`mullvad status -v`), no Tailscale exit selected, and the actual public egress. These are **post-boot checks**, not a claim of an OS-level kill switch; boot-time or outage traffic may otherwise use the ISP. Do not reboot an active host only to prove persistence; if the checks fail, hold target traffic and repair the chosen mode or recover a verified fallback.

## Scoped connectivity recovery

Preserve the exact DNS, browser, or proxy symptom. After two or three normal retries, distinguish a VPN path problem from local proxy/DNS configuration, then change one exit and verify. Retest one low-noise in-scope request (`getent hosts <host>` and a suitable `curl -I --max-time 15 https://<in-scope-host>/` or one browser reload). If still failing, record the result rather than cycling indefinitely.

Record previous/new manager and relay, city, public IP, exact symptom, command, verification, scoped retest and next action. Never rotate to evade target rules, rate limits, account bans, WAF enforcement, or explicit anti-VPN restrictions. Ask Ryushe before leaving the US West Coast, risking state-changing work, or after three failed changes. Never paste cookies, tokens or private URLs into chat.
