# Chromium Playwright-cache fallback integration dossier

- **Status:** approved for beta integration
- **Owner:** Hermes
- **Branch:** `fix/chromium-playwright-cache-fallback`
- **Base commit:** `a9db75eee30ffa8948e49c15887cc45c90afdcff`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-01
- **Owning feature branch/ref:** `fix/chromium-playwright-cache-fallback`
- **Latest immutable recovery checkpoint:** `e1255d0a21fc1f5db77e0f2d31a2b5250d011ced`
- **Feature implementation commit(s):** `c8d46364d31a78b670e2457cabe707830a141cbf`, `e1255d0a21fc1f5db77e0f2d31a2b5250d011ced`
- **Inspiration / canonical references:** Hoster onlinedoctor provisioner diagnosis.

## Intent

Permit the BBH checkout-local Python environment to use an already-installed host Playwright Chromium cache when Playwright is not installed inside BBH’s venv and no system Chromium binary is on `PATH`.

## Implemented contract

`chromium_test.py` first retains its existing Playwright API lookup. If that import/runtime lookup is unavailable, it searches only the conventional per-user `~/.cache/ms-playwright/chromium-*/chrome-*/chrome` location for an executable and selects the newest installed candidate. Explicit `--chrome-binary`, `CHROMIUM_TEST_CHROME`, and system PATH selection keep their current precedence.

## Evidence and review

- Tests and commands: `PYTHONPATH="$PWD" uv run --with pytest python -m pytest -q agents/test_chromium_test_launcher.py agents/test_browser_provisioner.py agents/test_hoster_mitm_lane.py` → 57 passed; `python3 -m py_compile skills/chromium-test/scripts/chromium_test.py`; `git diff --check`.
- Independent review: APPROVED after corrective rereview. It confirmed the synthetic-cache/denied-import test exercises `find_chrome_binary()` end to end; 57 focused tests passed in 2.09s.
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
- **Latest immutable recovery checkpoint:** `e1255d0a21fc1f5db77e0f2d31a2b5250d011ced`
- **Feature implementation commit(s):** `c8d46364d31a78b670e2457cabe707830a141cbf`, `e1255d0a21fc1f5db77e0f2d31a2b5250d011ced`
- **Exact resume point:** integrate the approved feature into a clean/current `beta`, remove this dossier from the integration lane, push beta, then update and dry-run the actual Hoster runtime checkout.
- **Working-tree state at handoff:** clean after the dossier checkpoint is committed.

## Decision gates

- **Integration gate:** focused tests, clean diff, independent approval, clean/current beta worktree.
- **Activation / cohort gate:** Hoster no-side-effect launcher dry-run.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-09-01 — Hoster diagnosis: the active BBH venv lacked the Playwright module while an executable Chromium already existed in the host Playwright cache; direct launcher dry-run failed `No Chromium/Chrome binary found`.
- 2026-09-01 — implementation checkpoint `c8d4636` passed 57 focused tests; independent review required an end-to-end launcher-path fallback regression.
- 2026-09-01 — corrective test checkpoint `e1255d0` denies `playwright` import and proves `find_chrome_binary()` reaches the synthetic cache executable; 57 focused tests passed.
- 2026-09-01 — independent corrective rereview APPROVED the candidate, including constrained lookup, precedence, end-to-end regression, 57-test suite, py_compile, and diff check.
