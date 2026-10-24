# XSS harness signal repair integration dossier

- **Status:** feature (final comment/query-mode release blockers repaired; awaiting independent re-review)
- **Owner:** bugfix subagent
- **Branch / owning ref:** `fix/xss-harness-signal`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-harness-signal`
- **Base commit:** `ca76506b830880c691316e8912a83ec50e4d313f` (`origin/beta`, fetched)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-24
- **Latest immutable recovery checkpoint:** `a5f1407c6403f793f61c24c19d73fdde211c6899`
- **Feature implementation commit(s):** `3b01996ce5fdbf421a8492fdf7e9d390127e9886`, `a5f1407c6403f793f61c24c19d73fdde211c6899`
- **Inspiration:** audited XSS framework/hunter signal defects and existing `agents/test_xss_framework.py` contracts.

## Intent and implemented contract

Correct marker-context classification from the marker's actual location, including unquoted attributes and JS strings containing HTML comment delimiters; preserve discovered parameter identity by route and non-probe query fields (such as `view=html` versus `view=json`) and probe that URL through screening, reflected, adaptive, and stored phases. Probe value changes and query-order changes within the same mode still dedupe by priority. Final finding dedupe retains distinct routes. Escaped markup and raw markup inside an HTML comment are not executable hunter candidates. Intact framework echoes wholly inside HTML comments remain Attempts, not findings; HTML comment breakouts and active echoes outside the comment remain candidates. This applies to standard and adaptive reflected paths. Blocked HTTP echoes produce Attempts, not findings, and tier progression continues past three blocked probes to deeper plausible variants. Framework HTTP probes record `reflected_intact`, never `executed`; only the optional Playwright browser verifier may set `confirmed`. CLI flags and JSON finding fields are unchanged. Heuristic candidates remain unconfirmed and require consumer/browser proof. No live target requests were made in this task.

## Evidence and review

- Red: `python3 -m pytest agents/test_xss_framework.py -q` → four expected regressions failed before implementation.
- Red: `python3 -m pytest agents/test_xss_hunter_signal.py agents/test_xss_framework.py -q` → escaped hunter payload failed before implementation.
- Green: `python3 -m pytest agents/test_xss_framework.py agents/test_xss_hunter_signal.py agents/test_xss_source_sites.py agents/test_xss_sink_sites.py -q` → 197 passed; `git diff --check` clean.
- Independent review identified P1 comment echo/blocked echo and premature tier stop; P2 route dedupe and context classification. New offline regressions failed against the prior checkpoint (4 failed, then additional comment/script ordering fixtures went red), then the focused suite passed (204 passed) and `git diff --check` passed. Final focused rerun: 204 passed; `git diff --check` clean.
- Broader attempted suite including `agents/test_xss_source_integration.py` and `agents/test_xss_defense_signal_routing.py` → 197 passed, three failed at that intermediate point: one hunter test subsequently fixed; two unrelated environment/baseline failures (source-map parser unavailable; expected XSS skill heading absent on beta). No edits to source-map component or skill.
- Independent re-review: pending parent/integration owner. Merge/ancestry evidence: base exactly `origin/beta` at branch creation and after fresh fetch; no merge or push. Source branch is this feature branch; no affected integrated descendants or propagation yet.
- Final release review regressions: `python3 -m pytest agents/test_xss_framework.py -q -k 'preserves_render_mode or reflected_comment_echo'` → 2 failed before fixes (query-mode merge and inert comment promoted to finding). Adaptive comment fixture also failed before its repair. Final offline suite: `python3 -m pytest agents/test_xss_framework.py agents/test_xss_hunter_signal.py agents/test_xss_source_sites.py agents/test_xss_sink_sites.py -q` → 208 passed; `git diff --check` clean. `origin/beta` remains `ca76506` after fetch. No target traffic.

## Blockers and deferred work

- Independent release review and beta integration are reserved for parent; rerun focused suite after integration. No browser/target execution was authorized. Browser proof is a per-finding downstream gate, not an integration test performed here.
- Broader suite environment: rerun `python3 -m pytest agents/test_xss_source_integration.py::test_source_map_module_exposes_named_input_with_bundle_provenance agents/test_xss_defense_signal_routing.py -q` when the checkout's source-map parser dependency is installed and baseline skill heading is reconciled. These failures are unrelated to changed paths.

## Interruption / resume handoff

- **Owning ref:** `fix/xss-harness-signal`
- **Latest immutable recovery checkpoint:** `a5f1407c6403f793f61c24c19d73fdde211c6899` (a subsequent dossier-only commit records this SHA).
- **Exact resume point:** independently re-review the comment/query-mode repair and focused tests; fetch `origin/beta` before integration; do not edit sibling chain-card branch or merge/push from this task.
- **Working-tree state at handoff:** clean after repair commit.

## Decision gates

- **Integration:** independent review of signal classification, scope/route provenance, and offline tests.
- **Activation:** none requested; no runtime switch.
- **Promotion:** not requested.

## Decision record

- 2026-10-24 — Created branch-local repair, offline regression tests and scoped docs clarification; review found P1/P2 regressions.
- 2026-10-24 — Corrected comment/blocked response candidate gating, deep-tier continuation, route-aware final dedupe, and context classification; re-review required before integration.
- 2026-10-24 — Final review blocked on inert framework comment finding and collapsed query render modes. Repaired both with offline red/green fixtures; independent re-review remains required.
