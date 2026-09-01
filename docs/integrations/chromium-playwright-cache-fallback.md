# Chromium Playwright-cache fallback integration dossier

- **Status:** corrective review ready
- **Owner:** Hermes
- **Branch:** `fix/chromium-playwright-cache-fallback`
- **Base commit:** `a9db75eee30ffa8948e49c15887cc45c90afdcff`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `fix/chromium-playwright-cache-fallback`
- **Latest immutable recovery checkpoint:** `c8d46364d31a78b670e2457cabe707830a141cbf`
- **Feature implementation commit(s):** `c8d46364d31a78b670e2457cabe707830a141cbf`
- **Inspiration / canonical references:** Hoster onlinedoctor provisioner diagnosis.

## Intent

Permit the BBH checkout-local Python environment to use an already-installed host Playwright Chromium cache when Playwright is not installed inside BBH’s venv and no system Chromium binary is on `PATH`.

## Implemented contract

`chromium_test.py` first retains its existing Playwright API lookup. If that import/runtime lookup is unavailable, it searches only the conventional per-user `~/.cache/ms-playwright/chromium-*/chrome-*/chrome` location for an executable and selects the newest installed candidate. Explicit `--chrome-binary`, `CHROMIUM_TEST_CHROME`, and system PATH selection keep their current precedence.

## Evidence and review

- Tests and commands: `PYTHONPATH="$PWD" uv run --with pytest python -m pytest -q agents/test_chromium_test_launcher.py agents/test_browser_provisioner.py agents/test_hoster_mitm_lane.py` → 57 passed; `python3 -m py_compile skills/chromium-test/scripts/chromium_test.py`; `git diff --check`.
- Independent review: initial review approved the constrained lookup and precedence but required an end-to-end fallback regression; corrective rereview is pending.
- Replay/cohort/fixture evidence: synthetic cache executable plus a denied `playwright` import proves `find_chrome_binary()` reaches the cache fallback through the real launcher lookup.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** Hoster launcher dry-run after beta deployment.
- **Command / fixture / environment needed:** clean Hoster beta runtime clone with its existing Playwright browser cache.
- **Trigger to run it:** after beta push.
- **Why it blocks integration, activation, or promotion:** does not block beta integration; blocks claiming the Hoster launch prerequisite is repaired.
- **Next completion step / successor reference:** review, merge, update Hoster clean runtime and active aiskillsync-beta launcher copy, run no-side-effect dry-run.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/chromium-playwright-cache-fallback`
- **Latest immutable recovery checkpoint:** `c8d46364d31a78b670e2457cabe707830a141cbf`
- **Feature implementation commit(s):** `c8d46364d31a78b670e2457cabe707830a141cbf`
- **Exact resume point:** independent reviewer must inspect `c8d4636` and this dossier-only checkpoint, then merge only after approval.
- **Working-tree state at handoff:** clean after the dossier checkpoint is committed.

## Decision gates

- **Integration gate:** focused tests, clean diff, independent approval, clean/current beta worktree.
- **Activation / cohort gate:** Hoster no-side-effect launcher dry-run.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-01 — Hoster diagnosis: the active BBH venv lacked the Playwright module while an executable Chromium already existed in the host Playwright cache; direct launcher dry-run failed `No Chromium/Chrome binary found`.
- 2026-09-01 — implementation checkpoint `c8d4636` passed 57 focused tests and is ready for independent review.
