---
name: android-adb
description: "Reach Ryushe's Android emulator for mobile security testing."
---

# Android ADB

Use this skill for dynamic testing of Ryushe's disposable Android emulator. It
covers the established ADB topology for Abommie and Hoster; it does not authorize
access to a physical device or alter program scope, rate, or test policy.

## When To Use

- Installing or pulling an APK; driving an app; screenshots; logcat; emulator
  storage inspection; or dynamic mobile validation.
- A BBH mobile/APK workflow needs a live device after static mapping or AppMap.
- `adb devices` is empty on Hoster and the agent needs to restore the existing
  emulator tunnel before declaring the device unavailable.

Do not use this skill for static APK analysis alone. Do not treat an unknown
physical device in `adb devices` as disposable.

## Topology

```text
Windows emulator (adbd at 127.0.0.1:5555)
  ^ mirrored WSL networking
Abommie / WSL -- reverse SSH tunnel --> Hoster (127.0.0.1:5555)
```

The emulator is Ryushe-owned and disposable. Installing, instrumenting, rooting,
pulling its app data, and clearing its state are allowed for authorized mobile
work. Confirm with Ryushe before performing any of those actions on a physical
or otherwise unidentified device.

## Required Preflight

1. Before any live target action, load `general-security-testing-policy`, then
   `live-testing-policy`. Those policies retain ownership of scope, account,
   rate, side-effect, backoff, attempt-recording, and stop decisions; this skill
   only supplies the local device transport. Load `resource-safety-policy`
   before APK, app-data, logcat, or other local artifact processing.
2. Read the applicable program's scope, authorization, and rate rules before
   interacting with a target app or backend.
3. Confirm the required host: use Abommie when the agent can work locally; use
   Hoster only when its reverse tunnel is healthy.
4. Run `adb devices` and verify the expected owned-emulator mapping **before
   any serial-targeted command**: Abommie must show `emulator-5554`; Hoster must
   show `127.0.0.1:5555`. These are two transports to the same emulator when
   both are visible locally. An extra, unmatched, physical, or unknown transport
   is a stop-and-ask condition, not a serial-selection exercise.
5. If the known transport is absent, restore only the documented Hoster tunnel
   or ask Ryushe; do not substitute another device or a public/Tailnet exposure.

## Abommie / WSL

The Windows Android Studio ADB server already exposes the emulator to WSL:

```bash
adb devices
adb -s emulator-5554 shell getprop ro.product.model
```

Use the local emulator transport. Do not use a Tailnet address here: `adb` is a
client of the Windows ADB server, which has no Tailnet route. Never run
`adb kill-server`, because it kills Android Studio's ADB server.

## Hoster

Hoster connects through the reverse tunnel established from Abommie:

```bash
adb devices
adb connect 127.0.0.1:5555
adb -s 127.0.0.1:5555 shell getprop ro.product.model
```

A successful `getprop` response proves the Hoster path can reach the emulator.
If `adb connect` or the shell command fails, repair the tunnel from Abommie;
do not substitute a public or Tailnet exposure.

## Restore The Hoster Tunnel

Run the installed helper on Abommie:

```bash
emu-adb-tailscale --tunnel
emu-adb-tailscale --tunnel --status
# Only for a tunnel owned by this task, or on explicit Ryushe instruction:
emu-adb-tailscale --tunnel --off
```

`--tunnel` is idempotent. It discovers the running emulator, verifies the local
ADB handshake, opens a reverse SSH tunnel to Hoster, and checks the remote ADB
endpoint. Treat a result containing `verified:` and the emulator model as the
completion condition. The tunnel is intentionally non-persistent: rerun the
helper after an emulator, WSL, host, or network restart.

## Known Traps

- Do not run `adb tcpip` against this emulator. Its ADB endpoint is already
  published at the emulator console port plus one (`emulator-5554` → port 5555).
- `emulator-5554` and `127.0.0.1:5555` can be two transports to one device;
  select one rather than treating them as separate emulators.
- Do not bind port 5555 in WSL. Mirrored networking shares the Windows port
  space and the emulator owns it. Use a different relay port if a relay is ever
  required.
- Use literal `127.0.0.1`, not `localhost`, for WSL forwarding: only IPv4
  loopback reaches the Windows endpoint reliably.
- Tailscale Serve may work for other peers but is not the Hoster path while its
  Mullvad routing/firewall policy is active. Use `--tunnel`.
- Do not use `tailscale nc` as the health check. Use `adb` or a plain socket.

## Verification And Handoff

1. Record only safe metadata: selected transport, model, host, and whether the
   tunnel helper reported verification. Do not place APK data, credentials, or
   target-app secrets in chat or shared notes.
2. Run one non-mutating command before the mobile task, such as:

```bash
adb -s <selected-serial> shell getprop ro.product.model
```

3. State the selected transport and whether access is local or tunnelled before
   invoking the next APK/mobile specialist workflow.
