# Chromium GPU host-test isolation dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/chromium-gpu-host-tests`
- **Base commit:** `68ef51e` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Owning feature branch/ref:** `fix/chromium-gpu-host-tests`
- **Latest immutable recovery checkpoint:** `2aad1468ddc20dc0aaeb9e7a50d9e54b37f6e8a1`
- **Feature implementation commit(s):** `2aad1468ddc20dc0aaeb9e7a50d9e54b37f6e8a1`
- **Inspiration:** Hoster beta acceptance run for automatic NVK Chromium launch.

## Intent

Isolate mocked launcher/KasmVNC unit tests from the host's installed `vulkaninfo` and occupied loopback web port. On Hoster, five tests failed despite an ordinary provisioner-owned `about:blank` browser rendering via NVK. Preserve the real integration probe and production code unchanged.

## Implemented contract

Tests whose scope is CA, display or KasmVNC startup now explicitly mock NVK detection or local port availability. NVK-specific tests still exercise probe parsing, timeout/fallback, backend selection and process-scoped device selection. No production behavior changes.

## Evidence and review

- Original Hoster beta suite: 5 failed, 84 passed. Three failures from mocked `subprocess.Popen` intercepting `vulkaninfo` probe; two from occupied loopback port 8463.
- Local `python3 -m pytest -q agents/test_chromium_test_launcher.py agents/test_browser_provisioner.py`: 89 passed.
- Independent review: 10 relevant tests passed; the isolation does not mask NVK-specific tests. Its full-suite attempt timed out after 300 seconds; Hermes's preceding 89-test local suite passed. Hoster rerun, beta merge and remote read-back: pending.

## Blockers and deferred work

- **Missing test or evidence:** final Hoster beta suite with local test-only correction.
- **Command:** `.venv/bin/python -m pytest -q agents/test_chromium_test_launcher.py agents/test_browser_provisioner.py` after reviewed beta checkout fast-forward.
- **Trigger:** reviewed merge and deployment.
- **Why:** no claim that the Hoster suite is green without the actual rerun.
- **Next:** independent review, beta integration, Hoster rerun and runtime read-back.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-gpu-host-tests`
- **Latest immutable recovery checkpoint:** `2aad1468ddc20dc0aaeb9e7a50d9e54b37f6e8a1`
- **Feature implementation commit(s):** `2aad1468ddc20dc0aaeb9e7a50d9e54b37f6e8a1`
- **Exact resume point:** integrate reviewed test correction, rerun Hoster tests.
- **Working-tree state at handoff:** clean after dossier follow-up.

## Decision gates

- **Integration gate:** independent review and focused local tests.
- **Activation gate:** Hoster full focused suite; existing real-browser NVK receipt remains valid.
- **Promotion gate:** separate stable decision.

## Decision record

- 2026-09-25 — created after Hoster suite reproduced host-dependent failures.
- 2026-09-25 — independent reviewer accepted test-only isolation; Hoster rerun remains required.
