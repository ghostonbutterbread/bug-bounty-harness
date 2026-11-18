# Nebula Browser Lane Scripts

## `hold_lane.py`

- **Purpose:** Hold the single-owner lock and CDP SSH tunnel with a live stdin
  pipe, confirm remote acquisition, expire after 900 seconds without explicit
  renewal, reap the exact local SSH child on exit, and start/stop an isolated
  generation-owned remote browser unit.
- **Invocation:** `bbh skills/nebula-browser-lane/scripts/hold_lane.py` as a
  foreground command in a task-owned Hoster user-systemd service. Read its
  printed receipt path. Run `bbh skills/nebula-browser-lane/scripts/hold_lane.py
  renew --receipt <path>` across tool calls; use `begin-handoff`,
  `complete-handoff`, `browser-start`, `browser-stop`, and `release` as documented
  in the [lane skill](../SKILL.md).
  Use `--help` for all options.
- **Inputs:** SSH configuration/key; optional `--timeout SECONDS` and
  `--receipt PATH`. Control operations require the private generation receipt.
- **Outputs:** Reports readiness, receipt path, and state/errors.
- **Mutates:** Opens the existing remote flock and loopback port forward; writes
  a private local receipt, coordination and operation locks, durable handoff and
  uncertain-start/stop markers, and remote generation tombstones and stop-operation
  receipts under `~/AI/nebula-lane`; starts or stops only the receipt's remote
  user-systemd browser unit. Stopping permanently fences that browser ID; a new
  start requires a new lease.
  Never removes the remote lock inode, browser profile, or VPN state.
- **Verification:** `pytest tests/test_nebula_browser_isolation.py tests/test_nebula_abandoned_lock_regression.py tests/test_nebula_disconnect_lock.py tests/test_nebula_browser_lane_skill.py -q` (local disposable SSH/lock and systemd fixtures, no live hosts).
- **Owner/scope:** Nebula Browser Lane; one named SSH session and lock only.
- **Limits:** Explicit renewal only; no in-flight detection, global SSH/CDP
  fencing, or retroactive timeout. SSH/network disconnect may be delayed. Handoff
  recovery requires the original receipt and the same local state directory.
  Browser leftovers outlive lease expiry; an occupied CDP port blocks startup
  until exact-receipt cleanup or legacy-owner reconciliation. Profiles remain.
- **Last verified:** 2026-11-17 (offline fixture; review pending).
