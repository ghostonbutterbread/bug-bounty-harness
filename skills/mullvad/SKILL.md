---
name: mullvad
description: "Check VPN egress and preserve the active manager safely."
---

# Mullvad egress

Use for VPN setup, West Coast exit rotation, or network-path recovery. Preserve
the working manager; prefer Tailscale for a new directed setup, not as a reason
to displace standalone Mullvad.

## Preflight — before external traffic or VPN action

1. Inspect the actual egress host and path, including remote hosts, proxies and
   containers: `tailscale get exit-node`, `tailscale status --json` if installed,
   `mullvad status -v` if installed, and effective IPv4/IPv6 routes as applicable.
   A connected tailnet alone is not an internet exit. Confirm the selected
   Tailscale exit is online and routes relevant traffic, or standalone Mullvad is
   connected and routes it. Repeat after network changes.
2. A failed status command does not prove a manager absent. Skip standalone
   status, disconnect, auto-connect and GUI checks only if verified absent. If
   presence or state is uncertain, or managers conflict, stop external traffic
   and ask Ryushe. If a route or exit fails verification, pause ordinary work;
   same-manager rotation remains subject to the gates below. Ask if recovery
   cannot be verified or requires a manager switch. Never silently use ISP egress.
3. Preserve the active manager; do not disconnect, layer, or switch managers to
   start work. A transition requires Ryushe's explicit direction. Never clear a
   selected Tailscale exit (`tailscale set --exit-node=` or equivalent) without
   his explicit direction; if direct rotation fails, pause and ask instead.
4. During recovery keep ordinary traffic paused. Send a bounded, non-sensitive
   public DNS/egress probe only after local manager status, the effective route
   for the probe's address family, and its DNS path support the intended VPN
   route. If unclear, do not probe; ask Ryushe. Resume only after verification.
   These checks are not a kill switch or proof of fail-closed protection.

**Fresh setup exception:** When Ryushe explicitly directs a fresh setup, no
Tailscale exit is selected and standalone Mullvad is verified absent or
disconnected, a working manager is not required to begin setup. First compare
`tailscale get exit-node`, `tailscale debug prefs` (RouteAll/ExitNodeID),
`tailscale status --json` (ExitNodeStatus), and effective routes if Tailscale is
installed. Require no selected, saved or effective exit; any saved ID,
mismatch or inaccessible state means stop for operator recovery, not overwrite.
If Tailscale is verified absent, skip its checks. Keep ordinary traffic paused
and public probes behind the gate above; follow the fresh setup procedure below.

For remote changes require a safe workload window and independently tested
recovery proven to survive the change; pre-switch LAN SSH alone is insufficient.
With a Tailscale exit, default to LAN access enabled unless Ryushe specifies a
host exception; when LAN access is used, verify its effective return route and
consider LAN DNS exposure. Verify independent SSH where relevant; remote changes
always require independently tested recovery. Do not restart Tailscale from the
only working tailnet SSH connection. Do not timeout or kill a slow Mullvad disconnect or interrupt
its daemon during DNS reset; monitor separately and coordinate recovery.

Optional: load `script-manager` and consult `scripts/README.md` for the read-only
IPv4 local snapshot `egress_inspect.py`. It does not detect public IP or verify
DNS, IPv6, ISP exposure or fail-closed protection. If unavailable, continue local
inspection; do not infer a manager is absent.

## Suspected IP-related incident

A CAPTCHA or 403 alone is not an IP-block classification. Record non-secret
incident context in the run record regardless of whether a host baseline can be
captured: symptom, independent reason for suspicion, affected path, time and
baseline availability. Do not log raw IPs, credentials or sensitive target data.

Load General Skills `script-manager` and consult `scripts/README.md` and
`egress_snapshot.md`. Verify installed help and run `egress_snapshot.py` on the
actual egress host using authorized remote control if needed; it has no `--host`.
The usual Hermes entrypoint is
`python3 "$HOME/.hermes/synced-skills/script-manager/scripts/egress_snapshot.py"`;
other runtimes use their resolved installed skill directory. After preflight,
promptly run `record KEY` with a stable, private, opaque run-owned incident key
(not an IP, secret or target identifier), and retain the key in run context.
If the helper is unavailable or recording fails, note the baseline is unknown;
do not substitute another public-IP probe. Continue other permitted investigation;
recording does not require refresh.

Later, optionally run `check KEY` or `refresh KEY` with that same key after all
safety gates. **Refresh can change the VPN exit**: under a shared lock it reports
`already_refreshed` if the host IP changed; if unchanged it may switch once to a
live-listed, different same-city West Coast exit of the current manager. It is
not automatic, guaranteed to switch, or a manager change. The lock coordinates
only cooperating processes of the same UID and shared filesystem view, not other
users or VPN tools. An uncertain or interrupted switch can leave a persistent
latch; pause ordinary traffic and do not remove it or retry speculatively. Follow
the installed helper's recovery conditions and coordinate operator recovery.

The baseline is a point-in-time post-block host-direct IPv4 observation: it
cannot establish the blocked IP if a switch preceded capture, accept an arbitrary
program-specific IP, or establish whether a remote proxy path changed. Refresh
deduplicates only the host-direct path; `different` means host IPv4 changed since
the baseline, not that the target unblocked. `same` or `unknown` is not permission
to rotate. Do not force rotation or bypass an unavailable baseline with a manual
switch. Protect private baseline data per the helper documentation. Program
rules, workload safety and recovery remain the caller's responsibility.

## Conditional procedures and verification

Read only the applicable sections of `prompts/mullvad-playbook.md`. Locate it
with `bbh --print-command prompts/mullvad-playbook.md`; compare `bbh --root` to
the physical source checkout of this projected skill. If provenance cannot be
established or the lanes differ, stop rather than reading a different lane.

- **Directed fresh setup or transition:** Read “Choose the path on each host”
  and, for a remote change, “Preflight gate for a remote handoff”. For fresh
  setup read “Directed fresh setup”; for a transition use the applicable one-time
  move or standalone fallback procedure. Do not silently change lockdown or
  disrupt workloads.
- **Rotation or recovery:** Read the current manager's “Tailscale rotation” or
  “Standalone CLI fallback / rotation” and, for failures, “Failure and rollback
  boundary” and “Scoped connectivity recovery”. Choose a different live-listed
  WA/OR/CA exit; ask before leaving that region and never use `auto:any`.
- **Boot, restart or LAN route drift:** Read “Boot/restart checks”; when LAN
  access is used, verify the effective return route, not just saved preference.
  Check the control paths applicable to that host.

After any change, including incident refresh, verify the manager, relay, intended
route, public DNS, relevant IPv6 and affected workloads on the actual path. Verify
independent remote access where relevant; it is required for a remotely managed
host, but not for a local host with no relevant remote access. Privately verify
Mullvad egress and rule out the ISP address
as the applicable playbook requires; do not place raw addresses or provider output
in transcripts or logs. If private verification is unavailable, keep traffic
paused and arrange operator verification. A changed host IP alone is insufficient.
Probe only after the local route and DNS gate; stop traffic if verification fails.
Record the symptom, prior/new manager and relay, command, verification and retest
without raw IPs. Ask Ryushe if an exit must be cleared, a manager switch is
needed, VPN use is prohibited, an account/application ban is involved,
state-changing work is at risk, or three exit changes fail. Changing exits never
authorizes evading target rules, rate limits, bans, WAF enforcement or explicit
VPN blocks. Fallback is an explicit verified transition, not automatic failover.
