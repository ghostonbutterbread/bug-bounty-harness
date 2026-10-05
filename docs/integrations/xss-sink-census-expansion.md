# XSS sink census expansion integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/xss-sink-census-expansion`
- **Base commit:** `baf6065b9ce06033df3a4fb8f71f323e782694dc`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-05
- **Owning feature branch/ref:** `feat/xss-sink-census-expansion`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** PortSwigger DOM-based XSS sink catalog and DOM Invader testcases; OWASP DOM-based XSS cheat sheet; React/Vue/Angular/Svelte/Lit and jQuery documentation. See `docs/xss-sink-inventory.md`.

## Intent

Expand BBH's existing `agents/js_analyzer.py` deterministic JS sink-farming vocabulary while preserving the existing `sinks` labels and non-exhaustive coverage contract. No live target testing, browser confirmation, or changes to XSS finding statuses.

## Implemented contract

The static inventory emits additional sorted category labels for HTML parsers, iframe srcdoc, event attributes, jQuery HTML/URL helpers and legacy review candidates, framework raw HTML/trust bypass, script text/URL/import, and URL navigation. Output remains heuristic `exhaustive: false`; a detected name is not taint or execution proof. Historical six labels remain.

## Evidence and review

- Tests and commands: checkout-local `./setup.sh --install-python-deps`; `.venv/bin/python -m pytest agents/test_js_analyzer.py -q` 73 passed; `git diff --check` clean.
- Independent review: pending.
- Replay/cohort/fixture evidence: 47 synthetic positive/negative sink fixtures in `agents/test_js_analyzer.py`.
- Merge/ancestry evidence: fetched `origin/beta` at `baf6065b9ce06033df3a4fb8f71f323e782694dc` before branching; remote-tracking beta has advanced four commits while working, so reconcile before review/integration.

## Blockers and deferred work

No known blocker. Runtime source-to-sink analysis and browser execution are deliberately not claimed by this static inventory.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/xss-sink-census-expansion`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** finish primary-source comparison, rerun tests, independent review, commit, then integrate into `beta` if gates pass.
- **Working-tree state at handoff:** intentionally uncommitted during implementation.

## Decision gates

- **Integration gate:** focused tests, independent review, clean current-beta reconciliation and beta smoke.
- **Activation / cohort gate:** not in scope; do not claim runtime deployment from a beta merge.
- **Promotion gate:** stable/main requires separate owner direction.

## Decision record

- 2026-10-05 — created from current origin/beta for an offline sink-inventory expansion.
