# XSS harness signal repair integration dossier

- **Status:** review-ready (independent acceptance review passed offline; integration pending)
- **Owner:** bugfix subagent
- **Branch / owning ref:** `fix/xss-harness-signal`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-harness-signal`
- **Base commit:** `ca76506b830880c691316e8912a83ec50e4d313f` (`origin/beta`, fetched)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Prior immutable recovery checkpoint:** `3b2648e959d006758c74aa994f981e4357cda9be`; current repair and dossier are committed together at branch tip.
- **Feature implementation commit(s):** `3b01996ce5fdbf421a8492fdf7e9d390127e9886`, `a5f1407c6403f793f61c24c19d73fdde211c6899`, `2a8ff65ad75d387f52c29ee0c4787ddcbedc2039`, `6471c93fd998f36ac673737fb2f7f34f0bfe8d3d`, `3b2648e959d006758c74aa994f981e4357cda9be`
- **Inspiration:** audited XSS framework/hunter signal defects and existing `agents/test_xss_framework.py` contracts.

## Intent and implemented contract

Correct marker-context classification from the marker's actual location, including unquoted attributes and JS strings containing HTML comment delimiters; preserve discovered parameter identity by route and non-probe query fields (such as `view=html` versus `view=json`) and probe that URL through screening, reflected, adaptive, and stored phases. Probe value changes and query-order changes within the same mode still dedupe by priority. Final finding dedupe retains distinct routes. Escaped markup and raw markup inside an HTML comment are not executable hunter candidates. Intact framework echoes wholly inside HTML comments remain Attempts, not findings; HTML comment breakouts and active echoes outside the comment remain candidates. This applies to standard and adaptive reflected paths. Blocked HTTP echoes produce Attempts, not findings, and tier progression continues past three blocked probes to deeper plausible variants. Framework HTTP probes record `reflected_intact`, never `executed`; only the optional Playwright browser verifier may set `confirmed`. CLI flags and JSON finding fields are unchanged. Heuristic candidates remain unconfirmed and require consumer/browser proof. JS-string/template reflections are now candidates only with a matching unescaped quote plus a statement-shaped call, active markup after an HTML script close, or an unescaped interpolation in an actual backtick template; inert `alert(1)` data and `${...}` in ordinary strings remain Attempts, not findings. Distinct quote, script-tag and interpolation mechanisms remain eligible independently. Framework reflected and adaptive candidates additionally share an all-echo inertness guard: intact payloads wholly in HTML comments or single/double-quoted script literals remain Attempts, including the exact nested `<script>alert(1)</script>` string echo; unescaped quote breaks, script closes followed by new markup, and any active second echo remain candidates. This is a conservative heuristic, not a full JavaScript parser or browser proof. No live target requests were made in this task.

## Evidence and review

- Reviewer follow-up: a quote in a JavaScript `//` comment made both the framework inert-echo guard and hunter delimiter heuristic misread `<script>// '\nconst v = `${alert(1)}`;</script>` as an ordinary string. Offline regressions failed before repair (framework and hunter active-template paths; ordinary string control passed). Shared `agents/js_literal_context.py` now skips line/block comments while tracking quote/escape state; template-expression prefixes are not classified as inert by the lexer. Detector and both gates use the same boundary. Ordinary quoted `${alert(1)}` remains inert; this is heuristic candidate classification, not browser proof. `python3 -m pytest agents/test_xss_framework.py agents/test_xss_hunter_signal.py agents/test_xss_source_sites.py agents/test_xss_sink_sites.py -q` → 222 passed; both CLI help entrypoints and `git diff --check` passed. No target traffic, merge, or push.
- Final reviewer reproduced the framework false finding from `<script>const v = '<script>alert(1)</script>';</script>`: `_only_in_html_comments` did not classify quoted JS data. Two offline path regressions went red (reflected and adaptive). Shared `_only_in_inert_contexts` now excludes only all-inert comment/quoted-script echoes; quote and script-close breakout controls remain candidates, while attempt outcomes remain `reflected_intact`. `python3 -m pytest agents/test_xss_framework.py agents/test_xss_hunter_signal.py agents/test_xss_source_sites.py agents/test_xss_sink_sites.py -q` → 219 passed; `git diff --check` clean. No browser-confirmation claim or live traffic.

- Red: `python3 -m pytest agents/test_xss_framework.py -q` → four expected regressions failed before implementation.
- Red: `python3 -m pytest agents/test_xss_hunter_signal.py agents/test_xss_framework.py -q` → escaped hunter payload failed before implementation.
- Green: `python3 -m pytest agents/test_xss_framework.py agents/test_xss_hunter_signal.py agents/test_xss_source_sites.py agents/test_xss_sink_sites.py -q` → 197 passed; `git diff --check` clean.
- Independent review identified P1 comment echo/blocked echo and premature tier stop; P2 route dedupe and context classification. New offline regressions failed against the prior checkpoint (4 failed, then additional comment/script ordering fixtures went red), then the focused suite passed (204 passed) and `git diff --check` passed. Final focused rerun: 204 passed; `git diff --check` clean.
- Broader attempted suite including `agents/test_xss_source_integration.py` and `agents/test_xss_defense_signal_routing.py` → 197 passed, three failed at that intermediate point: one hunter test subsequently fixed; two unrelated environment/baseline failures (source-map parser unavailable; expected XSS skill heading absent on beta). No edits to source-map component or skill.
- Independent re-review: pending parent/integration owner. Merge/ancestry evidence: base exactly `origin/beta` at branch creation and after fresh fetch; no merge or push. Source branch is this feature branch; no affected integrated descendants or propagation yet.
- Final release review regressions: `python3 -m pytest agents/test_xss_framework.py -q -k 'preserves_render_mode or reflected_comment_echo'` → 2 failed before fixes (query-mode merge and inert comment promoted to finding). Adaptive comment fixture also failed before its repair. Final offline suite: `python3 -m pytest agents/test_xss_framework.py agents/test_xss_hunter_signal.py agents/test_xss_source_sites.py agents/test_xss_sink_sites.py -q` → 208 passed; `git diff --check` clean. `origin/beta` remains `ca76506` after fetch. No target traffic.

- JS-string reviewer follow-up: offline `alert(1)` inside `const v = "..."` and mismatched quote both failed as false-positive candidates before the patch. Escaped template interpolation and mixed-case script close had focused red receipts during the repair. Final `python3 -m pytest agents/test_xss_hunter_signal.py agents/test_xss_framework.py agents/test_xss_source_sites.py agents/test_xss_sink_sites.py -q` → 216 passed; `git diff --check` clean. No browser proof, target traffic, merge, or push.

## Blockers and deferred work

- Independent release review and beta integration are reserved for parent; rerun focused suite after integration. No browser/target execution was authorized. Browser proof is a per-finding downstream gate, not an integration test performed here.
- Broader suite environment: rerun `python3 -m pytest agents/test_xss_source_integration.py::test_source_map_module_exposes_named_input_with_bundle_provenance agents/test_xss_defense_signal_routing.py -q` when the checkout's source-map parser dependency is installed and baseline skill heading is reconciled. These failures are unrelated to changed paths.

## Interruption / resume handoff

- **Owning ref:** `fix/xss-harness-signal`
- **Prior immutable recovery checkpoint:** `3b2648e959d006758c74aa994f981e4357cda9be`; current repair and dossier are committed together at branch tip.
- **Exact resume point:** independently review shared JS literal classification and both framework/hunter candidate gates, rerun focused tests and fetch `origin/beta` before integration; do not edit sibling chain-card branch or merge/push from this task.
- **Working-tree state at handoff:** clean after the current repair commit.

## Decision gates

- **Integration:** independent review of signal classification, scope/route provenance, and offline tests.
- **Activation:** none requested; no runtime switch.
- **Promotion:** not requested.

## Decision record

- 2026-10-24 — Created branch-local repair, offline regression tests and scoped docs clarification; review found P1/P2 regressions.
- 2026-10-24 — Corrected comment/blocked response candidate gating, deep-tier continuation, route-aware final dedupe, and context classification; re-review required before integration.
- 2026-10-24 — Final review blocked on inert framework comment finding and collapsed query render modes. Repaired both with offline red/green fixtures; independent re-review remains required.
- 2026-10-24 — Subsequent review found JS quoted data `alert(1)` promoted by token-only classification. Restricted candidate evidence to context breaks, covered inert and distinct breakout fixtures offline; independent review remains required.
- 2026-10-23 — Final reviewer found the framework's inert quoted script echo still promoted to a finding. Repaired both reflected and adaptive outputs at one predicate; offline red/green and breakout controls verified.
- 2026-10-24 — Independent bounded acceptance review of `9559172` found no reproducible blocker in the requested signal/chain-card scope; 222 focused tests passed. Approved for beta integration from feature ref; post-merge tests and activation remain separate.
