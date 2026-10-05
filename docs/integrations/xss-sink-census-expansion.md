# XSS sink census expansion integration dossier

- **Status:** blocked
- **Owner:** Hermes
- **Branch:** `feat/xss-sink-census-expansion`
- **Base commit:** `baf6065b9ce06033df3a4fb8f71f323e782694dc`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `feat/xss-sink-census-expansion`
- **Latest immutable recovery checkpoint:** `1f4fd4773a1469d1c33f6fc543e4584db2e184a7` (feature merged current beta; dossier-only update follows)
- **Feature implementation commit(s):** `0a91d65ad39c2f896070638bb29233bfc2ccb954`
- **Inspiration / canonical references:** PortSwigger DOM-based XSS sink catalog and DOM Invader testcases; OWASP DOM-based XSS cheat sheet; React/Vue/Angular/Svelte/Lit and jQuery documentation. See `docs/xss-sink-inventory.md`.

## Intent

Expand BBH's existing `agents/js_analyzer.py` deterministic JS sink-farming vocabulary while preserving the existing `sinks` labels and non-exhaustive coverage contract. No live target testing, browser confirmation, or changes to XSS finding statuses.

## Implemented contract

The static inventory emits additional sorted category labels for HTML parsers, iframe srcdoc, event attributes, jQuery HTML/URL helpers and legacy review candidates, framework raw HTML/trust bypass, script text/URL/import, and URL navigation. Output remains heuristic `exhaustive: false`; a detected name is not taint or execution proof. Historical six labels remain.

## Evidence and review

- Tests and commands: checkout-local `./setup.sh --install-python-deps`; `.venv/bin/python -m pytest agents/test_js_analyzer.py -q` 99 passed (189.98s) after jQuery parser, global eval, and event-name fixes; 73 focused parametrized cases; `git diff --check` clean. A prior full-suite attempt timed out at 120s; rerun succeeded at 360s.
- Independent review: initial reviewer findings (untyped method/property false positives, unqualified `open` regression, overstated source-map coverage) were fixed. A second reviewer of dd1580b found missed `$.parseHTML`, qualified global eval, and generic on-prefixed fields; all addressed with explicit regressions. Re-review of the resulting tip is pending.
- Replay/cohort/fixture evidence: 73 parametrized positive/negative sink fixtures plus an exact empty-bucket regression for native DOM and unrelated APIs in `agents/test_js_analyzer.py`.
- Merge/ancestry evidence: fetched `origin/beta` at `baf6065b9ce06033df3a4fb8f71f323e782694dc` before branching; merged updated `origin/beta` `869929d8e147fa9b6f35b0fd89d2e57ed69ab769` into the feature (`1f4fd4773a1469d1c33f6fc543e4584db2e184a7`), no conflicts. Focused XSS inventory remains green after reconciliation; broad script-policy test 96 passed / 1 unrelated pre-existing failure.

## Blockers and deferred work

- **Missing test or evidence:** `tests/test_script_policy.py::test_each_skill_index_has_complete_nonstale_records` fails because `skills/chromium-test/scripts/README.md` omits `browser_manager_row_repair.py`. Reproduced on unchanged beta at `869929d8e147fa9b6f35b0fd89d2e57ed69ab769` as well as this feature.
- **Command / fixture / environment needed:** add the helper's complete record in the Chromium Test script index in a separate task, then rerun `.venv/bin/python -m pytest agents/test_js_analyzer.py tests/test_script_policy.py -q`.
- **Trigger to run it:** after that independent beta repair lands and is merged into this feature.
- **Why it blocks integration, activation, or promotion:** broad declared script-policy verification remains red; feature-only 73 tests pass, but a required failed test cannot be misreported as green.
- **Next completion step / successor reference:** track the unrelated repair separately; review this feature's own diff meanwhile. Runtime source-to-sink analysis/browser execution is deliberately not claimed by this inventory.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-sink-census-expansion`
- **Latest immutable recovery checkpoint:** `1f4fd4773a1469d1c33f6fc543e4584db2e184a7` (feature merged current beta; dossier-only update follows)
- **Feature implementation commit(s):** `0a91d65ad39c2f896070638bb29233bfc2ccb954`
- **Exact resume point:** receive independent review, resolve concrete findings and rerun focused tests; independently repair the pre-existing Chromium Test script-index failure on its own task/branch before beta integration.
- **Working-tree state at handoff:** clean after the forthcoming dossier/BUGFIXES checkpoint commit.

## Decision gates

- **Integration gate:** focused tests, independent review, clean current-beta reconciliation and beta smoke.
- **Activation / cohort gate:** not in scope; do not claim runtime deployment from a beta merge.
- **Promotion gate:** stable/main requires separate owner direction.

## Decision record

- 2026-10-05 — created from current origin/beta for an offline sink-inventory expansion.
