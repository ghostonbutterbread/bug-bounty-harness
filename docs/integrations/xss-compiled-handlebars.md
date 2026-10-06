# Compiled Handlebars XSS candidate integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/xss-compiled-handlebars-20261006`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-compiled-handlebars`
- **Base commit:** `59e72403600c9e9035081ca32e7ac5c64f3bbd83` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `fix/xss-compiled-handlebars-20261006`
- **Latest immutable recovery checkpoint:** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196`
- **Feature implementation commit(s):** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196`
- **Inspiration:** Ryushe's empirical `globalV2.js` observation; local bounded bundle and synthetic regression fixtures. Seed: `Shared/skill_seeds/2026-10-06-xss-precompiled-handlebars-sink-gap.md`.

## Intent

Detect raw interpolations in compiled Handlebars output even when source syntax and `Handlebars.SafeString` are absent. Preserve legacy DOM-write routing and avoid declaring an exploitable XSS from static text.

## Implemented contract

`scan_sink_sites` emits a bounded candidate `Handlebars.compiledRawInterpolation(candidate)` in `framework_template_candidate` with offsets into the original bundle, requiring `template({` and `lookupProperty` context and a direct null-coalescing output append. Escaped interpolation, partial invocation, and generic null-coalescing DOM writes are excluded in focused fixtures. `js_analyzer.extract_signals` also populates the broad candidate family when that site is present; packet and module paths already consume the same site scanner. Documentation explicitly distinguishes candidate interpolation from a sink or proof.

## Evidence and review

- RED: first compiled-template fixture failed with zero raw candidates; cap regression then failed on false truncation.
- GREEN: `python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py -q` — 295 passed.
- `git diff --check` — clean.
- Local saved `globalV2.js` (~485 KB): 8 capped raw interpolation candidates; first offsets 207094, 212344, 214311, 215735; `framework_template_candidate` present and `sink_sites_truncated=true`. No live requests made.
- Independent review: pending.
- Merge/ancestry evidence: pending fetch and review gate.

## Blockers and deferred work

No blocker to static candidate coverage. This is intentionally not general Handlebars taint/escaping analysis; other compiler versions and long/dynamic expression forms still require manual review. No live XSS proof is claimed.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/xss-compiled-handlebars-20261006`
- **Latest immutable recovery checkpoint:** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196` (review the later dossier-only tip too).
- **Feature implementation commit(s):** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196`.
- **Exact resume point:** independent release review, then reconcile and integrate to beta if clean.
- **Working-tree state at handoff:** clean after dossier receipt commit.

## Decision gates

- **Integration gate:** independent review, fresh beta comparison, tests in feature and integrated beta.
- **Activation / cohort gate:** none requested; do not claim Hoster activation.
- **Promotion gate:** stable promotion requires explicit owner direction.

## Decision record

- 2026-10-06 — candidate matcher and regressions prepared for independent review.
