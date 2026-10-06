# Compiled Handlebars XSS candidate integration dossier

- **Status:** review-ready after function-scope repair; no beta integration yet
- **Owner:** Hermes
- **Branch:** `fix/xss-compiled-handlebars-20261006`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-compiled-handlebars`
- **Base commit:** `59e72403600c9e9035081ca32e7ac5c64f3bbd83` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `fix/xss-compiled-handlebars-20261006`
- **Latest immutable recovery checkpoint:** `6be416fea8979b564075839452f5e1e68cb870c5`
- **Feature implementation commit(s):** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196`, `b3f9653e879e2972808587e2a8b2950ce4cd482c`, `7ed87bd922cd5599013cd690b57824873fc77279`, `6be416fea8979b564075839452f5e1e68cb870c5`
- **Inspiration:** Ryushe's empirical `globalV2.js` observation; local bounded bundle and synthetic regression fixtures. Seed: `Shared/skill_seeds/2026-10-06-xss-precompiled-handlebars-sink-gap.md`.

## Intent

Detect raw interpolations in compiled Handlebars output even when source syntax and `Handlebars.SafeString` are absent. Preserve legacy DOM-write routing and avoid declaring an exploitable XSS from static text.

## Implemented contract

`scan_sink_sites` emits a bounded candidate `Handlebars.compiledRawInterpolation(candidate)` in `framework_template_candidate` with offsets into the original bundle, requiring `template({` and `lookupProperty` context and a direct null-coalescing output append. Escaped interpolation, partial invocation, and generic null-coalescing DOM writes are excluded in focused fixtures. `js_analyzer.extract_signals` also populates the broad candidate family when that site is present; packet and module paths already consume the same site scanner. Documentation explicitly distinguishes candidate interpolation from a sink or proof.

## Evidence and review

- RED: first compiled-template fixture failed with zero raw candidates; cap regression then failed on false truncation.
- GREEN: `python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py -q` — 302 passed after nested-function regression addition (2026-10-06).
- `git diff --check` — clean.
- Local saved `globalV2.js` (~485 KB): 8 capped raw interpolation candidates; first offsets 207094, 212344, 214311, 215735; `framework_template_candidate` present and `sink_sites_truncated=true`. No live requests made.
- Independent review: **blocked**. Fresh `git fetch origin beta` confirms `origin/beta` at `59e72403600c9e9035081ca32e7ac5c64f3bbd83`, with only the implementation and dossier commits unique to the feature. Independent rerun: `python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py -q` — 295 passed; `git diff --check origin/beta...HEAD` clean.
- Reviewer probes against `scan_sink_sites` demonstrated four false-positive classes: `+(null!=(a=s(l(t,"name")))?a:"")` with `s=e.escapeExpression` was labeled raw; a matching generic ternary **after** the compiled template was labeled Handlebars because `template({`/`lookupProperty` remained in the preceding 8 KB; and a malformed ternary `?b:""` was joined to a later `?a:""` suffix, producing one span across two expressions. A ternary passed as a function argument was also labeled a direct output append. These violate the stated raw/direct/context contract, not merely the acknowledged attacker-control uncertainty.
- Repair: failing regression fixtures added for all four classes; balanced template-object and assignment-expression boundaries, return-append check, and escaped-helper alias exclusion now pass those fixtures. Saved `globalV2.js` still yields eight capped candidates, first offsets unchanged. A later gate found comment handling unsound (below).
- Fresh independent gate: `git fetch origin beta` confirmed `59e72403600c9e9035081ca32e7ac5c64f3bbd83`; focused suite `python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py -q` passed 299. Reviewer found a new direct-return false positive: `_direct_return_append` treats `return` in a JavaScript comment as a real return. Reproducer: `x.template({0:function(x,t){var a,l=x.lookupProperty;/* return */var buf="<p>"+(null!=(a=l(t,"name"))?a:"");return buf}});` yields `Handlebars.compiledRawInterpolation(candidate)` at offset 78 even though the append is in a local assignment, not a direct return. `scan_sink_sites` from `agents.xss_sink_sites` suffices to reproduce; filter hits by that signature. Conversely `+/*(*/(null!=(a=l(t,"name"))?a:"")` inside a legitimate return is missed because `_direct_return_append` counts parentheses inside a block comment. The repair's lexical boundary is not yet sound for comments; no merge.
- Repair: `_js_code_chars` skips comments and quoted text while matching delimiters and finding code `return`; both reviewer cases were RED then GREEN. A positive fixture additionally includes `/*}*/` inside the compiled template to check balanced-object boundaries. Focused suite 301 passed; saved bundle still yields the same eight capped candidates and broad family. New independent gate pending.
- Third independent gate: fetched `origin/beta` at `59e72403600c9e9035081ca32e7ac5c64f3bbd83`; `python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py -q` passed 301; `git diff --check origin/beta...HEAD` clean. **Blocked:** `_direct_return_append` treats a nested function's `return` as the template function's direct output. Reproducer (run `scan_sink_sites(s)` and filter signature `Handlebars.compiledRawInterpolation(candidate)`): `s='x.template({0:function(x,t){var a,l=x.lookupProperty;return "<p>"+(function(){return "<b>"+(null!=(a=l(t,"name"))?a:"")},"</p>")}});'` returns a candidate at `[90,119)`. This valid JS uses a comma expression that discards the nested function; executing the template yields `<p></p>` with no lookup or callback invocation. The field is not interpolated into the output. This violates the direct-output contract and persists after the comment-aware repair.
- Repair: brace depth from `template({` confines the direct return to the compiled program body (depth two), excluding nested function returns and discarded callbacks. Reviewer repro RED then GREEN; focused suite 302 passed. Saved `globalV2.js` still produces eight capped raw candidates at prior offsets. Fourth independent gate pending.
- No integration performed; beta remains at fetched base.

## Blockers and deferred work

Block release until a fresh independent review accepts the function-scope repair. Other compiler versions and long/dynamic expression forms still require manual review. No live XSS proof is claimed.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/xss-compiled-handlebars-20261006`
- **Latest immutable recovery checkpoint:** `6be416fea8979b564075839452f5e1e68cb870c5` (review the later dossier-only tip too).
- **Feature implementation commit(s):** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196`, `b3f9653e879e2972808587e2a8b2950ce4cd482c`, `7ed87bd922cd5599013cd690b57824873fc77279`, `6be416fea8979b564075839452f5e1e68cb870c5`.
- **Exact resume point:** review function-scope repair and integrate only after independent acceptance.
- **Working-tree state at handoff:** clean after repair commit.

## Decision gates

- **Integration gate:** independent review, fresh beta comparison, tests in feature and integrated beta.
- **Activation / cohort gate:** none requested; do not claim Hoster activation.
- **Promotion gate:** stable promotion requires explicit owner direction.

## Decision record

- 2026-10-06 — candidate matcher and regressions prepared for independent review.
- 2026-10-06 — independent release gate **rejected**: escaped expression, post-template ternary, cross-expression suffix, and function-argument false positives reproduced. Retain feature and dossier for repair; no beta merge.
- 2026-10-06 — repaired four reviewer-proven cases via balanced context and expression checks; 299 tests passed and saved bundle still routes candidate. Request a new independent gate.
- 2026-10-06 — fresh independent release gate **rejected**: comment text contaminates direct-return depth/boundary, creating a false positive on `/* return */` before a local buffer assignment and a false negative on `/*(*/` in a direct return. Focused 299-test suite passes but lacks these cases; beta remains unchanged.
- 2026-10-06 — fixed comment handling and added both reviewer reproductions; 301 focused tests pass, saved bundle still yields candidates. Third independent gate pending.
- 2026-10-06 — third independent release gate **rejected**: a nested `return` in a discarded function expression is classified as template output, despite runtime `<p></p>` and no field lookup. Retain feature and dossier; do not merge beta.
- 2026-10-06 — constrained direct-output append to compiled program body; nested-function regression passes with 302 focused tests and saved-bundle candidate persistence. Fourth gate pending.
