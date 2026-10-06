# Compiled Handlebars XSS candidate integration dossier

- **Status:** review-ready after repair; new independent gate pending
- **Owner:** Hermes
- **Branch:** `fix/xss-compiled-handlebars-20261006`
- **Worktree:** `/home/ryushe/worktrees/bbh-xss-compiled-handlebars`
- **Base commit:** `59e72403600c9e9035081ca32e7ac5c64f3bbd83` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning feature branch/ref:** `fix/xss-compiled-handlebars-20261006`
- **Latest immutable recovery checkpoint:** `b3f9653e879e2972808587e2a8b2950ce4cd482c`
- **Feature implementation commit(s):** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196`, `b3f9653e879e2972808587e2a8b2950ce4cd482c`
- **Inspiration:** Ryushe's empirical `globalV2.js` observation; local bounded bundle and synthetic regression fixtures. Seed: `Shared/skill_seeds/2026-10-06-xss-precompiled-handlebars-sink-gap.md`.

## Intent

Detect raw interpolations in compiled Handlebars output even when source syntax and `Handlebars.SafeString` are absent. Preserve legacy DOM-write routing and avoid declaring an exploitable XSS from static text.

## Implemented contract

`scan_sink_sites` emits a bounded candidate `Handlebars.compiledRawInterpolation(candidate)` in `framework_template_candidate` with offsets into the original bundle, requiring `template({` and `lookupProperty` context and a direct null-coalescing output append. Escaped interpolation, partial invocation, and generic null-coalescing DOM writes are excluded in focused fixtures. `js_analyzer.extract_signals` also populates the broad candidate family when that site is present; packet and module paths already consume the same site scanner. Documentation explicitly distinguishes candidate interpolation from a sink or proof.

## Evidence and review

- RED: first compiled-template fixture failed with zero raw candidates; cap regression then failed on false truncation.
- GREEN: `python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py -q` — 299 passed after four additional regression cases (2026-10-06).
- `git diff --check` — clean.
- Local saved `globalV2.js` (~485 KB): 8 capped raw interpolation candidates; first offsets 207094, 212344, 214311, 215735; `framework_template_candidate` present and `sink_sites_truncated=true`. No live requests made.
- Independent review: **blocked**. Fresh `git fetch origin beta` confirms `origin/beta` at `59e72403600c9e9035081ca32e7ac5c64f3bbd83`, with only the implementation and dossier commits unique to the feature. Independent rerun: `python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py -q` — 295 passed; `git diff --check origin/beta...HEAD` clean.
- Reviewer probes against `scan_sink_sites` demonstrated four false-positive classes: `+(null!=(a=s(l(t,"name")))?a:"")` with `s=e.escapeExpression` was labeled raw; a matching generic ternary **after** the compiled template was labeled Handlebars because `template({`/`lookupProperty` remained in the preceding 8 KB; and a malformed ternary `?b:""` was joined to a later `?a:""` suffix, producing one span across two expressions. A ternary passed as a function argument was also labeled a direct output append. These violate the stated raw/direct/context contract, not merely the acknowledged attacker-control uncertainty.
- Repair: failing regression fixtures added for all four classes; balanced template-object and assignment-expression boundaries, return-append check, and escaped-helper alias exclusion now pass. Saved `globalV2.js` still yields eight capped candidates, first offsets unchanged. Second independent gate pending.
- No integration performed; beta remains at fetched base.

## Blockers and deferred work

Block release until a fresh independent review accepts the repaired matcher and its tests. Other compiler versions and long/dynamic expression forms still require manual review. No live XSS proof is claimed.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/xss-compiled-handlebars-20261006`
- **Latest immutable recovery checkpoint:** `b3f9653e879e2972808587e2a8b2950ce4cd482c` (review the later dossier-only tip too).
- **Feature implementation commit(s):** `9b3c64f4604dd7a2f0bb5d6eafb3c8b765b94196`, `b3f9653e879e2972808587e2a8b2950ce4cd482c`.
- **Exact resume point:** review the repair commit against the rejected gate, then integrate to beta only if independently accepted.
- **Working-tree state at handoff:** clean after review-decision commit.

## Decision gates

- **Integration gate:** independent review, fresh beta comparison, tests in feature and integrated beta.
- **Activation / cohort gate:** none requested; do not claim Hoster activation.
- **Promotion gate:** stable promotion requires explicit owner direction.

## Decision record

- 2026-10-06 — candidate matcher and regressions prepared for independent review.
- 2026-10-06 — independent release gate **rejected**: escaped expression, post-template ternary, cross-expression suffix, and function-argument false positives reproduced. Retain feature and dossier for repair; no beta merge.
- 2026-10-06 — repaired four reviewer-proven cases via balanced context and expression checks; 299 tests passed and saved bundle still routes candidate. Request a new independent gate.
