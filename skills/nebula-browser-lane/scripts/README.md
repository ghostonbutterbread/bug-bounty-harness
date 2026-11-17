# Nebula Browser Lane Scripts

## `hold_lane.py`

- **Purpose:** Hold the single-owner lock and CDP SSH tunnel with a live stdin
  pipe, confirm remote acquisition, and reap the local SSH child on exit.
- **Invocation:** `bbh skills/nebula-browser-lane/scripts/hold_lane.py` as a
  foreground command in a task-owned Hoster user-systemd service. See the
  [lane skill](../SKILL.md) for Hoster/agent launch, inspection, and exact-unit
  stop. Use `--help` for command help.
- **Inputs:** No arguments or input files; uses the existing SSH configuration
  and key.
- **Outputs:** Reports readiness on stdout and errors on stderr.
- **Mutates:** Opens the existing remote lane lock and loopback port forward;
  never removes the lock, browser profile, readiness file, or VPN state.
- **Verification:** `pytest tests/test_nebula_disconnect_lock.py tests/test_nebula_browser_lane_skill.py -q` (local disposable SSH/lock fixture, no live hosts).
- **Owner/scope:** Nebula Browser Lane; one named SSH session and lock only.
- **Limits:** Not an idle detector. SSH/network disconnect detection may be delayed.
- **Last verified:** 2026-11-17 (offline fixture; review pending).
