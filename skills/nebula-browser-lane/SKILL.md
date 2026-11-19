---
name: nebula-browser-lane
description: "Captcha/login on Nebula after harness GPU fails."
---

# Nebula true-browser lane

Headed `google-chrome-stable` on device `nebula` for a human at the physical
screen after the harness GPU/headed lane (`chromium-test`) already failed:
login, signup, password-reset, magic-link Continue, CAPTCHA, and
authenticity/IP blocks. Not a WAF-payload bypass.

When a prompt is on Nebula's screen, reserve the human handoff as described
below **before** asking Ryushe to interact. Once reservation succeeds, tell
Ryushe immediately (site + what to click) and wait. Do not loop image
challenges on harness Chromium (including llvmpipe WebGL).

## Policy boundary

`captcha-policy` owns a CAPTCHA. Its Nebula exception is this lane: after
`chromium-test` has already failed, and Ryushe is at Nebula's screen, this is
the physical-screen path. It does not replace `chromium-handoff` for an
existing harness browser. Do not relaunch the harness browser to qualify for
handoff. Do not drop Mullvad, change egress to beat the challenge, or evade
rate controls. This human-present lane is not an unattended device capability;
a new device flow is not the original browser's session or challenge.

The eligible human-controlled physical-screen flow remains available: the human
performs the egress check and target interactions at Nebula's screen, while the
agent waits. An active `operator_review`, 429 cooldown, or other applicable stop
still prohibits the corresponding target interaction; handoff does not reset it.

Before any agent-driven target interaction, establish the dedicated task-scoped
local MITM required by `proxy-routing-policy` and verify the actual browser proxy
route and exact CA trust. The same policy applies to other active agent browser
traffic, including an agent-driven egress check. If those prerequisites are
missing or unverified, stop and report the missing prerequisite instead of driving
the browser; human presence and a VPN check do not establish the proxy or trust.
The launch command below does not establish or verify a task proxy or CA. Do not
configure or alter the remote device blindly, infer an unattended capability, or
use CDP to drive target interaction until the prerequisites are actually met.

## Connection

- Device: `nebula` at `100.124.250.25` (mesh address), hostname `Nebula`,
  Arch Linux, user `ryushe`. Key auth verified 2026-11-10.
- Browser: `google-chrome-stable` (`/usr/bin/google-chrome-stable`). Firefox
  and `mullvad` are installed. Do not launch Firefox.
- Desktop: KDE Plasma Wayland (`/run/user/1000/wayland-0`). XWayland exposes
  `:0`. A non-interactive SSH session does not inherit the desktop session, so
  the launch command must export display variables itself. `DISPLAY=:0` is the
  default. If Chrome misbehaves under XWayland, stop and coordinate; do not
  substitute an unmanaged launch command.
- Run every `ssh nebula` command on the harness host that already has the
  `nebula` alias and `~/.ssh/nebula_ed25519` (currently Hoster). Ghost does
  not have the key. Do not copy the private key to another machine.
- SSH: `ssh nebula` (IdentitiesOnly, StrictHostKeyChecking accept-new,
  pubkey fingerprint `SHA256:F0GSROTz2q14wRX9TxfuRyRGEQTmRg+uIERSMrgAJnM`).
  If the mesh address moves, update the alias `HostName`, not the key.

## Hard requirements (owner-designated)

1. **Single-owner lock.** The lock-holder SSH session below owns the machine
   for the segment; subagents it spawns inherit that ownership — do not
   acquire again. Never steal, block-wait, or force-kill a live holder. If
   `-n` fails, report "locked" and defer.
2. **Never drop Mullvad** for target work (no `disconnect`, disable, or
   lockdown-off) — that exposes the owner's home residential IP to the target.
   Do not rotate or otherwise change egress to beat a CAPTCHA. Manager detection
   and coordinated handling are separate unresolved prerequisites: a host may
   use Tailscale Mullvad rather than a standalone Mullvad daemon. Do not assume
   a manager or issue direct relay/reconnect commands. For any requested egress
   change, stop and report until the applicable coordinator and this owner's
   never-drop protection are independently verified; retain the US West Coast
   location constraint. Without verified protection and actual browser egress,
   stop before target navigation.
3. **Verify egress inside Chrome** before any target navigation: have the human
   load `https://am.i.mullvad.net/json` in the physical-screen flow and confirm
   `mullvad_exit_ip: true` + expected relay. Host-side `curl` is not enough.
   Agent-driven browser traffic requires the task proxy and CA gate above first.
4. **No secrets on the device; dedicated profile only.** Never open or copy
   the owner's personal Chrome profiles.
5. **Chrome only — Firefox is off-limits.** Firefox is the owner's personal
   browser: never launch, update, configure, profile-manage, read, or clean it
   (including `~/.mozilla`). All lane work uses `google-chrome-stable` with the
   dedicated `--user-data-dir`; nothing else on the device gets launched.
6. **All agent work lives in `~/AI/`.** Every agent-created file on the device
   (browser profiles, logs, scripts, artifacts) goes under `$HOME/AI/` —
   create it if missing. The only exceptions are the ephemeral lock in
   `/tmp` and Mullvad's own state. Nothing is written to the home directory
   root or the owner's existing folders. Nebula holds personal state outside
   `~/AI/`; do not touch it.

## Lock + CDP tunnel (one SSH, hold for the whole segment)

Run the holder **on Hoster**, the host with the Nebula key. An OMP or other
agent already running on Hoster can launch it as a task-owned foreground service
under Hoster's user manager (load `hoster-ssh` first). The foreground command is
`bbh skills/nebula-browser-lane/scripts/hold_lane.py`. Record the exact unit and
resolved BBH executable; do not launch it with a bare SSH background command.
Check for an existing matching task-owned unit before starting a replacement.

On Hoster, in the agent's shell:

```bash
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
unit="hoster-nebula-lane-$(date -u +%Y%m%dT%H%M%SZ)-$$"
bbh_bin="$(command -v bbh)" || { echo 'bbh not found on Hoster' >&2; exit 1; }
printf 'Record unit=%s bbh=%s\n' "$unit" "$bbh_bin"
"$bbh_bin" --root
```

Confirm the printed checkout is the intended reviewed lane before dispatch:

```bash
systemd-run --user --unit="$unit" --property=MemoryHigh=2G \
  --property=MemoryMax=3G --property=CPUWeight=100 -- \
  "$bbh_bin" skills/nebula-browser-lane/scripts/hold_lane.py --timeout 600
```

This example sets a 10-minute lease. Use `--timeout 900` for 15 minutes;
omitting the option also defaults to 900 seconds. Renew comfortably inside the
chosen interval.

From a different machine, use `hoster-ssh`'s `hoster_user_unit.py` helper to
dispatch the same foreground command, not an invented OMP spawn command. First
use its bounded SSH inspection to discover Hoster's absolute `bbh` executable
and verify the selected checkout with `bbh --root`. Then, on the controller,
substitute that observed path for `/absolute/hoster/path/to/bbh`:

```bash
HELPER="$HOME/.hermes/synced-skills/hoster-ssh/scripts/hoster_user_unit.py"
unit="hoster-nebula-lane-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 "$HELPER" --unit="$unit" -- /absolute/hoster/path/to/bbh \
  skills/nebula-browser-lane/scripts/hold_lane.py --timeout 600
printf 'Record unit=%s\n' "$unit"
```

Inspect the recorded unit on Hoster (restore `unit` to the exact recorded value
in a new shell). From elsewhere, run these bounded commands through the
`hoster-ssh` inspection route. Check `ControlGroup` is below the user manager,
not `ssh.service`, and that `ActiveState=active`:

```bash
systemctl --user show "$unit" -p ActiveState -p ControlGroup -p MainPID
journalctl --user -u "$unit" --no-pager -n 50
```

Wait for `nebula lane lock held (ssh pid ...)` in that unit's journal before
starting Chrome or target work. The holder keeps SSH stdin open, and the remote
`flock -n -E 73 /tmp/nebula-lane.lock` command prints a random readiness token
on the SSH stream only after acquisition, then reads until stdin EOF. The helper
checks that token, reports a conflict or connection/forwarding/readiness error,
and exits if SSH exits. A busy local port can fail before the remote flock is
attempted; do not call every SSH failure a lock conflict. On SSH disconnect the
remote read reaches EOF and releases its lock once the server observes the
disconnect; a partition can delay detection. Never remove or replace the lock
file. Do not start a second `flock` or duplicate `-L` after readiness.

The readiness token proves acquisition at that instant; a live local unit or
SSH PID is **not atomic proof** of continuing remote ownership. Loss can race a
separate remote command or its cleanup. If the unit exits, connection state is
uncertain, or ownership cannot be established, stop lane work and preserve the
ambiguous state; do not kill other SSH processes or touch another owner's
resources.

### Explicit lease activity and human handoff

The holder defaults to **900 seconds since its last explicit renewal**, not
observed browser, SSH, or task activity. The readiness journal line prints the
private receipt path; record that path and the exact unit. Keep the receipt
private: it authorizes this generation. All cooperating invocations must use the
same Hoster account, HOME, and `XDG_STATE_HOME` as the holder (default
`$HOME/.local/state`); the coordination and durable handoff marker live under
`$XDG_STATE_HOME/nebula-lane` or `$HOME/.local/state/nebula-lane`. Do not alter
or delete them to resolve ambiguity. From a new tool call on Hoster, restore the
recorded receipt path and run:

```bash
receipt='/absolute/path/from/the/holder/journal'
bbh skills/nebula-browser-lane/scripts/hold_lane.py renew --receipt "$receipt"
```

Renew before starting each device operation and periodically while operating,
well within the selected timeout. **In-flight SSH/CDP commands are not detected or
protected automatically**; continue renewing during long operations. A failed
renewal means stop immediately, preserve state and re-acquire before proceeding.
The holder serializes renewal with expiry, but this does not atomically fence
separate raw SSH/CDP commands. Unmanaged raw SSH/CDP and other hosts do not
obey this cooperative control. Existing pre-lease SSH holders are not converted
retroactively; the same remote flock still blocks a new holder.

Before asking a human to interact, successfully reserve the handoff:

```bash
bbh skills/nebula-browser-lane/scripts/hold_lane.py begin-handoff --receipt "$receipt"
# Only after that succeeds, ask the human to act and wait for confirmation.
bbh skills/nebula-browser-lane/scripts/hold_lane.py complete-handoff --receipt "$receipt"
```

The reservation pauses expiry and persists privately even if the holder dies.
After confirmed human completion, `complete-handoff` resumes the live lease or,
if the holder died, clears the matching reservation and requires a fresh
acquisition. Never clear it based on elapsed time. If the receipt is lost or
ownership/handoff is ambiguous, stop and coordinate with the owner rather than
seizing the lane. Close the exact lease when finished with `release --receipt
"$receipt"` (or stop the recorded unit after completing handoff). The release
reply starts shutdown; inspect the recorded unit for exit before considering
local cleanup complete. Expiry and release close only this holder's SSH stdin
and reap its exact child; they do not
kill Chrome, remove the profile or lock inode, or touch another session. SSH
server disconnect detection may be delayed. Set `--timeout SECONDS` on the
holder's launch command for the chosen ordinary-work interval.

## Headed Chrome (generation-owned profile, loopback CDP)

```bash
bbh skills/nebula-browser-lane/scripts/hold_lane.py browser-start --receipt "$receipt"
```

Only after success, connect on Hoster with
`chromium.connect_over_cdp("http://127.0.0.1:9333")`. The command renews the
current lease, checks a real remote bind of `127.0.0.1:9333`, and starts and
checks a uniquely named user-systemd unit. Its independent non-secret browser ID
selects `$HOME/AI/nebula-lane/runs/<browser_id>/chrome-profile`; the generation
capability is never put in the remote profile path or process arguments. Chrome
is headed, with `DISPLAY=:0`, and starts at `about:blank`. A CDP connection is
not evidence of task proxy routing or CA trust; do not drive network traffic
without the agent-proxy gate above. Have the human verify VPN egress inside
Chrome before target navigation and pause for the human on the physical screen.
Do not use this lane to replace a `chromium-handoff` CAPTCHA path.

If the remote port is busy, **do not connect**: an old or legacy browser may
still be listening. A confirmed `remote CDP port busy` result means this start
never launched; use the exact old receipt to stop the old browser, if available,
then retry with the current receipt. Without the old receipt, ask the owner to
reconcile the legacy session; never kill it or reuse its profile. Other failures,
interruptions, or SSH timeouts may leave an owned unit running: do not attach;
run `browser-stop` with this attempted start's exact receipt until it succeeds,
then release and acquire a fresh lease before another start.
The bind check and later start are cooperative, not atomic fencing of unmanaged
processes or a network partition. A successful start is not a continuing lease:
renew during work and stop on uncertainty.

## Cleanup

Close Playwright on Hoster and, after any human handoff is completed, stop the
exact generation-owned browser before releasing the lease:

```bash
bbh skills/nebula-browser-lane/scripts/hold_lane.py browser-stop --receipt "$receipt"
bbh skills/nebula-browser-lane/scripts/hold_lane.py release --receipt "$receipt"
```

`browser-stop` also accepts an expired old receipt and stops only its exact named
unit. It verifies inactivity or a `LoadState=not-found` result; it does not
require the current lease or stop a successor's different unit. A handoff
reservation and browser operations are serialized: if either reports busy,
wait and retry, and never ask the human before handoff succeeds. Apart from the
confirmed busy-port refusal described above, a dispatched start or stop with an
interrupted, failed, or lost reply has an unknown outcome and blocks handoff,
browser start, and acquisition. A failure to launch the local
SSH executable is definitive for that new operation, but never clears an
already uncertain one. Retry `browser-stop` with the **same exact receipt**
until it succeeds; if the receipt or marker is damaged, stop and ask the owner
to reconcile.

A stop durably tombstones its browser ID, even if the unit has not appeared yet;
a delayed start of that ID is refused. That ID cannot be restarted: release and
acquire a new lease for another browser. Never delete local markers or remote
`$HOME/AI/nebula-lane/browser-generations` or `stop-operations` records while
late SSH commands could still arrive. Interrupted control/browser commands
return failure; their remote outcome may still be unknown. The helper never
deletes profiles or the lock inode.
Keep receipts private and record retained profile leftovers. If the holder times
out, its lock can expire while Chrome remains: a successor can acquire the lock
but must not start or attach while the port is occupied; exact cleanup or owner
reconciliation is then required.
This is a fail-closed partial recovery, not seamless automatic browser cleanup.
Legacy receipts without `browser_id` cannot be used for browser cleanup.

Stop only this task's exact recorded Hoster unit, then inspect its state and
journal for exit (use the `hoster-ssh` bounded inspection/stop route from a
controller). Restore `unit` to the recorded value in a new shell:

```bash
systemctl --user stop "$unit"
systemctl --user show "$unit" -p ActiveState -p ControlGroup
journalctl --user -u "$unit" --no-pager -n 50
```

Stopping the unit closes the local SSH transport; remote lock release depends
on the server observing EOF/disconnect and is not proved by the local exit.
Do not reset, restart, or stop any other unit. Leave the owner's personal
Chrome, Firefox, Plasma, and Mullvad running. Record the final relay, uncertain
remote lock state, and leftovers in run notes.

## Not for

- Payload-level WAF/filter blocks → `waf-live-policy`
- Ordinary harness headed/GPU Chromium that is already working → `chromium-test`
- Bulk request volume — this lane is for interactive, human-adjacent flows
- JavaScript evidence. This is a physical-screen host, not a page or endpoint
  analysis skill. Do not mine scripts to choose or skip it.

`captcha-policy` owns the CAPTCHA decision and routes this physical-screen
exception here. Load it when a CAPTCHA appears. Do not treat a rate-control
stop as permission to continue on Nebula.

## Related skills

- If a CAPTCHA appears on any authorized flow, load `captcha-policy`.
- If the block is a WAF rule on the payload, load `waf-live-policy`.
- If harness headed/GPU Chromium is enough, load `chromium-test`.
- If relay selection is unclear, load `mullvad`. The never-drop rule above
  still governs.

## Evidence

Write the handoff note under
`$HARNESS_SHARED_BASE/{program}/ghost/nebula-browser-lane/`.

Record the site, what the human was asked to click, Mullvad relay confirmed
inside Chrome, lock acquire/release, and leftovers. Do not record cookies,
passwords, or the SSH private key.

## Scripts

See the [script index](scripts/README.md) for the lane lock/tunnel holder.
