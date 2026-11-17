---
name: nebula-browser-lane
description: "Captcha/login on Nebula after harness GPU fails."
---

# Nebula true-browser lane

Headed `google-chrome-stable` on device `nebula` for a human at the physical
screen after the harness GPU/headed lane (`chromium-test`) already failed:
login, signup, password-reset, magic-link Continue, CAPTCHA, and
authenticity/IP blocks. Not a WAF-payload bypass.

When a prompt is on Nebula's screen, tell Ryushe immediately (site + what to
click) and wait. Do not loop image challenges on harness Chromium (including
llvmpipe WebGL).

## Policy boundary

`captcha-policy` owns a CAPTCHA. Its Nebula exception is this lane: after
`chromium-test` has already failed, and Ryushe is at Nebula's screen, this is
the physical-screen path. It does not replace `chromium-handoff` for an
existing harness browser. Do not relaunch the harness browser to qualify for
handoff. Do not drop Mullvad, change egress to beat the challenge, or evade
rate controls. A non-CAPTCHA authenticity block may rotate Mullvad only while
it stays connected, and only inside the hard requirement below.

## Connection

- Device: `nebula` at `100.124.250.25` (mesh address), hostname `Nebula`,
  Arch Linux, user `ryushe`. Key auth verified 2026-11-10.
- Browser: `google-chrome-stable` (`/usr/bin/google-chrome-stable`). Firefox
  and `mullvad` are installed. Do not launch Firefox.
- Desktop: KDE Plasma Wayland (`/run/user/1000/wayland-0`). XWayland exposes
  `:0`. A non-interactive SSH session does not inherit the desktop session, so
  the launch command must export display variables itself. `DISPLAY=:0` is the
  default. If Chrome misbehaves under XWayland, quit only the lane Chrome and
  relaunch with `WAYLAND_DISPLAY=wayland-0` as well.
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
   Do not rotate or otherwise change egress to beat a CAPTCHA. For a
   non-CAPTCHA authenticity block, rotate only while connected; stay US West
   Coast:
   `mullvad relay set location us <city> && mullvad reconnect --wait`
   (standalone daemon, e.g. `us-sea-wg-406`; a different relay = new egress).
3. **Verify egress inside Chrome** before any target navigation: load
   `https://am.i.mullvad.net/json` in the driven tab and confirm
   `mullvad_exit_ip: true` + expected relay. Host-side `curl` is not enough.
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
  "$bbh_bin" skills/nebula-browser-lane/scripts/hold_lane.py
```

From a different machine, use `hoster-ssh`'s `hoster_user_unit.py` helper to
dispatch the same foreground command, not an invented OMP spawn command. First
use its bounded SSH inspection to discover Hoster's absolute `bbh` executable
and verify the selected checkout with `bbh --root`. Then, on the controller,
substitute that observed path for `/absolute/hoster/path/to/bbh`:

```bash
HELPER="$HOME/.hermes/synced-skills/hoster-ssh/scripts/hoster_user_unit.py"
unit="hoster-nebula-lane-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 "$HELPER" --unit="$unit" -- /absolute/hoster/path/to/bbh \
  skills/nebula-browser-lane/scripts/hold_lane.py
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
resources. A still-running SSH holder may retain the lock after an agent
abandons it: this is not idle detection or an idle timeout. Explicitly stop the
recorded unit at the end.

## Headed Chrome (dedicated profile, loopback CDP)

```bash
ssh nebula 'export DISPLAY=:0 XDG_RUNTIME_DIR=/run/user/$(id -u)
PROFILE=$HOME/AI/nebula-lane/chrome-profile
mkdir -p "$PROFILE"
google-chrome-stable --user-data-dir="$PROFILE" \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9333 \
  --remote-allow-origins="*" --no-first-run --no-default-browser-check \
  --start-maximized about:blank >$HOME/AI/nebula-lane/chrome-lane.log 2>&1 &'
```

No `--headless`. CDP binds `127.0.0.1` only. On the harness host:
`chromium.connect_over_cdp("http://127.0.0.1:9333")` (Chrome needs a few
seconds before the endpoint answers). Pause for the human on the physical
screen. Do not use this lane to replace a `chromium-handoff` CAPTCHA path.

If that Chrome is unusable under XWayland, quit only the lane process and
relaunch the same command with `WAYLAND_DISPLAY=wayland-0` added to the
`export`. Do not switch browsers.

## Cleanup

Close Playwright on Hoster. Separate Nebula SSH commands have no established
atomic remote-owner guarantee if lock loss or a replacement owner races them.
Therefore do **not** automatically kill Chrome, delete its profile, remove the
lock inode, or remove the old readiness file based on a local PID/unit check.
Preserve and record leftovers; if remote ownership is uncertain, stop and
coordinate safe cleanup with the owner. In particular, do not touch another
owner's session.

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
