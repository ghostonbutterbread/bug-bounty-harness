# XSS sink taxonomy gap expansion

- **Status:** independently approved for beta integration
- **Owner:** Hermes
- **Branch:** `feat/xss-sink-taxonomy-expansion`
- **Base commit:** `58706890ddb4cb4e882bbe781a4a9157a806dc5b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-06
- **Owning worktree:** `/home/ryushe/projects/bug_bounty_harness/xss-sink-taxonomy-expansion`
- **Latest immutable recovery checkpoint:** `f0f7cc5fc099cf86c347ce7d2b902e404e3f563d` (feature implementation `5e65941`, merged fetched `origin/beta` `76105d6`)

## Intent and inspiration

Compare primary PortSwigger DOM XSS and DOM Invader sink references with CodeQL, Dalfox, Semgrep, OWASP and relevant framework APIs. Extend the existing `agents/js_analyzer.py` deterministic `sinks` review labels only where missing sink families can be recognized without promoting safe or unrelated operations to high-confidence XSS leads. Keep the six historical labels, the bundle-text-only boundary, sorted category output, and `signal_coverage.exhaustive: false`. No live target testing.

## Implemented contract

Second pass extends existing sink categories with literal bracket DOM writes and navigation, iframe `srcdoc` attribute-node writes, jQuery HTML setters/`appendTo`/`prependTo`, script text/import APIs, Angular Renderer2, Lit SVG, fbjs parsing and AngularJS trust-as-JS. Adds separate candidate labels for bounded one-hop jQuery/script aliases, jQuery AJAX script mode, and Vue runtime template compilation. `docs/xss-sink-inventory.md` records primary-source links, omitted noisy or legacy signatures, and confidence limits. Existing JSONL labels and non-exhaustive bundle-text analysis remain intact. No target traffic.

## Evidence and review

- Baseline: beta `5870689` was the published Hoster beta at feature creation. PortSwigger Academy/DOM Invader and CodeQL, Semgrep, Dalfox, XSStrike, jQuery, Vue, Angular and Lit primary-source comparisons informed the bounded additions; see `docs/xss-sink-inventory.md`.
- Checkout-local `.venv/bin/python -m pytest agents/test_js_analyzer.py tests/test_script_policy.py -q`: **188 passed** after implementation; positive and exact-negative sink fixtures cover new patterns. `git diff --check` passed. No live target testing.
- Reconciled against fetched `origin/beta` `76105d6` with merge `f0f7cc5`. Checkout-local `.venv/bin/python -m pytest agents/test_js_analyzer.py tests/test_script_policy.py -q`: **189 passed** after reconciliation; `git status` clean before this dossier-only update.
- Final independent review approved `eabfa79` against beta `76105d6`: **174 analyzer**, **199 combined** tests and **18 targeted probes** passed; `git diff --check` clean. No unresolved actionable finding. Fetched `origin/beta` still `76105d6`; beta integration worktree clean. Integration check and publication remain pending.

## Blockers and deferred work

No blocker. A finite regex vocabulary cannot discover every sink or prove source-to-sink taint; dynamic aliases, computed properties, browser state and source-map-only modules remain human-review territory. Cite accepted signatures in `docs/xss-sink-inventory.md`; record intentionally deferred noisy or non-XSS terms there.

## Integration decision

Approve the reviewed feature for the existing `beta` lane only. Remove this temporary dossier on the integration target while retaining the feature-history record. Deferred: no live-target proof or runtime activation is implied by static inventory tests; the XSS skill must keep the scoped collection and non-exhaustive caveats. Stable/main remains out of scope.

## Resume point

Merge this approved feature into clean current beta, retire this dossier on target, run integrated checks and inspect the changed paths. Publish beta and verify remote/Hoster runtime only as a separate rollout; do not imply activation from a local merge.

## Decision gates

- Integration: primary-source attribution, representative positive/negative fixtures, non-exhaustive language, independent review, current beta reconciliation and integrated smoke.
- Publication/runtime: explicit beta push, remote revision readback, Hoster clean-checkout refresh and active route verification only if requested for this new change.
- Stable/main promotion: separate owner direction.
