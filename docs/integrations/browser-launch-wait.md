# Configurable browser launch wait

**Branch:** `fix/browser-launch-wait-configurable`
**Base / target:** `origin/beta` (b7e64c3) → `beta`
**Status:** implemented and verified on Hoster.

## Intent

`browser_provisioner.py start()` waited a hardcoded 8 seconds for the launcher to
write its private record, then stopped the unit and released the lease. On Hoster
that budget is unreachable: the launcher must stand up a display and wait for
Chromium to reach CDP first. Every provisioning attempt therefore failed with
`launcher did not produce a valid private record`, and the failure text named no
timeout, so two separate hunts (epicgames, quixel) recorded it as an unexplained
"browser coverage gap" and misattributed the cause.

Evidence: 0-byte `*.launch.json` records date back to 2026-09-07. A successful
launch on this host measured `waited_seconds: 11.49` — just past the old ceiling.

## Implemented contract

- `LAUNCH_WAIT_SECONDS` module constant, overridable via
  `BROWSER_LAUNCH_WAIT_SECONDS`, defaulting to 45s (previously a literal 8).
- The failure detail now names the elapsed budget and the override variable, so
  the next agent can diagnose it from the emitted JSON alone.

Default-only behaviour change: a slow launch now succeeds instead of being
killed. Callers that relied on failing fast within 8s would wait longer, but that
path produced no usable browser, so nothing depended on it.

## Evidence

- `python -m py_compile` clean.
- Live: `browser_provisioner.py request epicgames anon --display-backend auto`
  returned `"status": "started"` with `waited_seconds` 11.49 and 5.69 across two
  runs; CDP answered `Chrome/148.0.7778.96`; the page then loaded
  `www.epicgames.com` through the Cloudflare managed challenge.
- Chromium ran sandboxed via the Playwright binary already covered by the
  `hoster-playwright-chromium` AppArmor profile; no `--no-sandbox` and no
  `kernel.apparmor_restrict_unprivileged_userns` change were needed.

## Not in scope here

`setup.sh --install-python-deps` installs only `requirements-bounty-core.txt`, so
`requests`, `bs4`, `PyYAML` and `urllib3` are missing from a fresh `.venv` and 10
harness scripts fail on import. Ryushe chose to leave `setup.sh` alone for now;
the live venvs were repaired by hand. Recorded in `BUGFIXES.md`.

## Next

Review and merge to `beta`. No follow-up branch.
