# Chromium automatic NVK backend integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/chromium-auto-vulkan`
- **Base commit:** `3a25123` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Owning feature branch/ref:** `fix/chromium-auto-vulkan`
- **Latest immutable recovery checkpoint:** `aadaefb9bb1589d50315a080da01a33854bbcced`
- **Feature implementation commit(s):** `aadaefb9bb1589d50315a080da01a33854bbcced`, `670d17e3319e12adeca5804fa681524e49b81a5e`
- **Inspiration / canonical references:** Hoster Vulkan wrapper and `chromium-test` GPU guidance.

## Intent

Hoster Nouveau/NVK exposes a real GPU through Vulkan, but KasmVNC/Xvfb GLX falls back to llvmpipe. A session-only `CHROMIUM_TEST_CHROME` wrapper selected Vulkan; ordinary provisioner launches selected ANGLE/GL and lost the GPU after reboot. Move backend selection into the provisioner-owned launcher without a shared session setting, changing unrelated browser lanes, or spoofing hardware identity.

## Implemented contract

For ordinary headed browser requests, the provisioner masks inherited `CHROMIUM_TEST_CHROME` for the browser unit (the Hoster user manager retained a wrapper), then the launcher runs a bounded `vulkaninfo --summary` probe and selects a real discrete Mesa NVK device, ANGLE/Vulkan flags, and a process-scoped `MESA_VK_DEVICE_SELECT`. Missing/failed probes fall back to existing GL. Headless, explicit binary and external graphics backend retain their prior behavior; external mode retains an explicitly selected wrapper. No target traffic is needed for detection and no user-manager environment is changed. Process-level selection is not a claim of in-page WebGL or hardware rendering; that requires a disposable real browser check.

## Evidence and review

- Tests: `python3 -m pytest -q agents/test_chromium_test_launcher.py agents/test_browser_provisioner.py` — 89 passed locally. Regressions were red before implementation (missing detector and inherited wrapper masking).
- Hoster evidence: `vulkaninfo --summary` lists NVK discrete `10de:1b82` and llvmpipe CPU; the existing wrapper sets `MESA_VK_DEVICE_SELECT=10de:1b82` plus Vulkan flags; headed GL path uses `--use-angle=gl`. Host `eglinfo -B` also exposes NV134 and llvmpipe, so it is not in-page proof.
- **Independent review:** first review of `aab381d` found Hoster's user-manager retained the wrapper; follow-up `670d17e` masks it per ordinary browser unit. Independent re-review found no blocking code issue and reran 89 passing tests. Runtime in-page acceptance remains pending.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** normal provisioner-owned headed browser, without any `CHROMIUM_TEST_CHROME` setting, returns a non-llvmpipe NVK in-page renderer and cleans up exact unit/profile. Command: task-owned disposable `about:blank` request on Hoster under user-systemd, verify CDP/renderer, release and finish only its own task proxy. Trigger: reviewed beta code deployed on Hoster with admission capacity. This blocks claiming GPU runtime acceptance, not local code review.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-auto-vulkan`
- **Latest immutable recovery checkpoint:** `aadaefb9bb1589d50315a080da01a33854bbcced`
- **Feature implementation commit(s):** `aadaefb9bb1589d50315a080da01a33854bbcced`, `670d17e3319e12adeca5804fa681524e49b81a5e`
- **Exact resume point:** integrate reviewed branch into beta, deploy Hoster, run disposable ordinary producer with in-page GPU check.
- **Working-tree state at handoff:** clean after documentation checkpoint.

## Decision gates

- **Integration gate:** focused tests, independent review, current beta reconciliation.
- **Activation / cohort gate:** Hoster runtime projection plus normal disposable headed provisioner check with real renderer; preserve existing browser units.
- **Promotion gate:** beta acceptance and explicit owner decision for stable.

## Decision record

- 2026-09-25 — created after tracing GLX-versus-Vulkan behavior and ordinary launcher selection.
- 2026-09-25 — independently reviewed with no blocking code finding; activation awaits real in-page renderer acceptance on Hoster.
