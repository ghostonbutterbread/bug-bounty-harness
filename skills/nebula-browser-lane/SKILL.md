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

Run this with bash on the harness host, not on a machine that lacks the
`nebula` key. Do not use `ssh -f`: it returns 0 before the remote `flock`
status is known, so a held lock looks successful and the session pid is lost.

```bash
token=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
ssh -T -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -L 9333:127.0.0.1:9333 nebula \
  "flock -n /tmp/nebula-lane.lock sh -c 'echo $token > /tmp/nebula-lane.ready; exec sleep infinity'" &
lane_pid=$!
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if ! kill -0 "$lane_pid" 2>/dev/null; then
    wait "$lane_pid"
    echo "nebula lane locked; defer"
    exit 1
  fi
  if ssh -o BatchMode=yes -o ConnectTimeout=5 nebula "grep -qx '$token' /tmp/nebula-lane.ready"; then
    ready=1
    break
  fi
  sleep 0.5
done
if [ "$ready" != 1 ]; then
  kill "$lane_pid" 2>/dev/null || true
  wait "$lane_pid" 2>/dev/null || true
  echo "nebula lane locked; defer"
  exit 1
fi
echo "nebula lane lock held by pid $lane_pid"
```

Record `lane_pid`. Lock lifetime = that SSH process. If it dies, the lock
releases — re-acquire honestly. Do not start a second `flock` or a duplicate
`-L`. If the pid is lost, do not kill unrelated SSH sessions to recover it.

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

Close Playwright on the harness host. Quit only the lane Chrome on Nebula,
then stop the recorded tunnel pid. The `[u]` in the pattern keeps `pkill`
from matching its own command line.

```bash
ssh nebula 'pkill -f "[u]ser-data-dir=$HOME/AI/nebula-lane" || true'
ssh nebula "grep -qx '$token' /tmp/nebula-lane.ready && rm -f /tmp/nebula-lane.ready"
kill "$lane_pid" 2>/dev/null || true
wait "$lane_pid" 2>/dev/null || true
```

Leave the owner's personal Chrome, Firefox, Plasma, and Mullvad running.
When the engagement closes, remove the lane directory on Nebula, not on the
harness:

```bash
ssh nebula 'rm -rf "$HOME/AI/nebula-lane"'
```

Note final relay location and any leftovers in run notes before releasing the
lock.

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
