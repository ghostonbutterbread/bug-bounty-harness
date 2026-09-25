# Chromium automatic NVK backend integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `fix/chromium-auto-vulkan`
- **Base commit:** `3a25123` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Owning feature branch/ref:** `fix/chromium-auto-vulkan`
- **Latest immutable recovery checkpoint:** `aadaefb9bb1589d50315a080da01a33854bbcced`
- **Feature implementation commit(s):** `aadaefb9bb1589d50315a080da01a33854bbcced`
- **Inspiration / canonical references:** Hoster Vulkan wrapper and `chromium-test` GPU guidance.

## Intent

Hoster Nouveau/NVK exposes a real GPU through Vulkan, but KasmVNC/Xvfb GLX falls back to llvmpipe. A session-only `CHROMIUM_TEST_CHROME` wrapper selected Vulkan; ordinary provisioner launches selected ANGLE/GL and lost the GPU after reboot. Move backend selection into the provisioner-owned launcher without a shared session setting, changing unrelated browser lanes, or spoofing hardware identity.

## Implemented contract

For ordinary headed browser requests, the launcher runs a bounded `vulkaninfo --summary` probe and selects a real discrete Mesa NVK device, ANGLE/Vulkan flags, and a process-scoped `MESA_VK_DEVICE_SELECT`. Missing/failed probes fall back to existing GL. Headless, explicit binary, external graphics backend, and environment-selected wrappers retain their prior behavior. No target traffic is needed for detection and no user-manager environment is changed. Process-level selection is not a claim of in-page WebGL or hardware rendering; that requires a disposable real browser check.

## Evidence and review

- Tests: `python3 -m pytest -q agents/test_chromium_test_launcher.py agents/test_browser_provisioner.py` — 88 passed locally. Regression was red before implementation (missing detector).
- Hoster evidence: `vulkaninfo --summary` lists NVK discrete `10de:1b82` and llvmpipe CPU; the existing wrapper sets `MESA_VK_DEVICE_SELECT=10de:1b82` plus Vulkan flags; headed GL path uses `--use-angle=gl`. Host `eglinfo -B` also exposes NV134 and llvmpipe, so it is not in-page proof.
- Independent review: pending.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** normal provisioner-owned headed browser, without any `CHROMIUM_TEST_CHROME` setting, returns a non-llvmpipe NVK in-page renderer and cleans up exact unit/profile. Command: task-owned disposable `about:blank` request on Hoster under user-systemd, verify CDP/renderer, release and finish only its own task proxy. Trigger: reviewed beta code deployed on Hoster with admission capacity. This blocks claiming GPU runtime acceptance, not local code review.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-auto-vulkan`
- **Latest immutable recovery checkpoint:** `aadaefb9bb1589d50315a080da01a33854bbcced`
- **Feature implementation commit(s):** `aadaefb9bb1589d50315a080da01a33854bbcced`
- **Exact resume point:** review code and tests, commit, independent review, integrate beta, deploy Hoster, run disposable ordinary producer with in-page GPU check.
- **Working-tree state at handoff:** clean after help-text follow-up checkpoint.

## Decision gates

- **Integration gate:** focused tests, independent review, current beta reconciliation.
- **Activation / cohort gate:** Hoster runtime projection plus normal disposable headed provisioner check with real renderer; preserve existing browser units.
- **Promotion gate:** beta acceptance and explicit owner decision for stable.

## Decision record

- 2026-09-25 — created after tracing GLX-versus-Vulkan behavior and ordinary launcher selection.
