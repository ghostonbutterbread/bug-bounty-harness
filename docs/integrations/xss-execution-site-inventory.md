# XSS execution-site inventory

- **Status:** review-ready after reconciliation with fetched beta
- **Owner:** Hermes
- **Branch:** `feat/xss-execution-site-inventory`
- **Base:** `28c8a27e205c5525ae6654db44d5618f01c95753` (`origin/beta`)
- **Target:** `beta`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/xss-execution-site-inventory`
- **Recovery checkpoint:** `3907b41e733995423d3572f3b2ed9c9a7413936c` (implementation), reconciled merge `2dec820`

## Intent and boundary

Ryu corrected the earlier category-count framing: enumerate **individual XSS execution destinations and API/attribute call sites**, including conditional ones, rather than only broad `sinks` labels. Compare primary PortSwigger, DOM Invader, CodeQL, Dalfox, XSStrike, Semgrep, and framework sources with the BBH script. Keep existing JSONL `sinks` and signal-coverage compatibility. Add per-site evidence (signature, review tier, bounded location, source artifact) to the same JS inventory, and scan packeted source-map modules where feasible. No live target testing or claim of exhaustive coverage; server-only templates require a separate input surface, not a fabricated bundle hit.

## Acceptance

- Distinct, source-backed signatures for useful browser/framework execution contexts; conditional and legacy cases labeled as such, not XSS proof.
- Bounded per-site hit locations and stable JSONL/packet handoff while preserving existing bucket consumers.
- Positive/negative fixtures including getter/equality/non-script/URL-scheme boundaries and a real offline `inventory` fixture.
- Checkout-local tests, independent review, beta reconciliation and integration verification. Publication/Hoster activation only after review through normal lane workflow.

## Evidence

- Base worktree created from fetched and published `origin/beta` `28c8a27`.
- Baseline checkout-local `./setup.sh --install-python-deps` and `.venv/bin/python -m pytest agents/test_js_analyzer.py tests/test_script_policy.py -q`: 199 passed.
- Read-only research compared PortSwigger Academy and DOM Invader scenarios with CodeQL, Dalfox, XSStrike, Semgrep and framework documentation. Academy's 7 browser and 20 jQuery entries and DOM Invader's 77 scenarios are not distinct execution-sink counts. PortSwigger `document.domain` is context, not execution. `docs/xss-sink-inventory.md` records source links, candidate tiers and omissions.
- Implemented `agents/xss_sink_sites.py` with 218 named, bounded signature rules (108 event spellings), plus script-alias cases. `agents/js_analyzer.py inventory` retains `sinks` and adds `sink_sites` with signature/family/tier/character offsets, explicit truncation, metadata/manifest totals, and packetized embedded-source-map hits. It does not scan server templates or skipped modules; no target traffic was sent for this feature.
- `.venv/bin/python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py tests/test_script_policy.py -q`: 306 passed. `git diff --check`: clean. Offline inventory and source-map module packet fixtures assert persisted offsets and packet routing; positives and negatives cover receivers, getters, assignments, URL/event/HTML paths.
- `origin/beta` advanced to `140c096` during implementation (12 commits beyond feature base); merged it into this feature at `2dec820`. Reconciled `.venv/bin/python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py tests/test_script_policy.py -q`: 306 passed; `git diff --check`: clean. Implementation checkpoint `3907b41`. Independent review, beta merge, publication and Hoster activation pending.

- Independent review of `003dd09` against `140c096` requested three changes: chained jQuery insertion lost site evidence, broad `$(el)` candidates exhausted the constructor cap ahead of `$(html)`, and script-alias evidence crossed a shadowed `const`. Reviewer passed 306 tests, checkout import/CLI probes, and bounded scans; no provenance/offset defect. Resolved with bounded jQuery-preserving chains, narrowed dynamic constructor candidates including `$(location.hash)`, and a rebinding stop; added positive/negative regression fixtures.
- Post-fix `.venv/bin/python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py tests/test_script_policy.py -q`: 315 passed; `git diff --check`: clean. Focused 116 site tests passed, and dense chained-jQuery/constructor fixtures under 1.1 MB completed below one second each. New review of this tip is pending.

- Fresh re-review of `0c4b285` approved the two jQuery corrections but blocked on script-alias shadowing: function/arrow parameters and uninitialized declarations were not fenced, and a valid outer binding after an inner block was incorrectly discarded. Replaced permanent rebound stop with bounded block-scope tracking; positive and negative fixtures cover those cases. `.venv/bin/python -m pytest agents/test_xss_sink_sites.py agents/test_js_analyzer.py tests/test_script_policy.py -q`: 316 passed, and `git diff --check` clean. Awaiting independent final-tip approval.

- Final-tip review of `35a4379` verified prior three corrections but found two remaining alias-scope false positives: assignment to an outer binding inside a block was lost after that block, and an expression-bodied arrow parameter was not shadowed. The bounded scope tracker now marks the nearest actual binding on assignment and handles expression-bodied arrows through the terminating semicolon. Fixtures cover both negatives and valid sites after block/arrow scope; 117 site tests and 199 analyzer/policy tests pass, `git diff --check` clean.
- After the alias fix at `51b23b0`, `origin/beta` advanced to `4939907` with non-overlapping papercut guidance/tests. Reconciled by merge `6879d5d2a0983d5f59974074e15a705c0aa2ee94`; the same 316 combined tests pass from this feature worktree, and `git diff --check` is clean. Next: final-tip independent review, then beta integration gate.

- Review of `8e7d9eb` caught first/middle multi-parameter arrow shadowing (both block and expression bodies). Generalized bounded arrow parameter-list binding detection rather than special-casing one alias position; first/middle negatives and post-arrow positives now pass. Combined checkout-local suite: 316 passed; `git diff --check` clean. Independent final-tip review pending before beta integration.

- Review of `fc1df8b` confirmed prior fixes but found object/class method parameters shadowing a script alias. Extended the bounded scope scanner to recognize method parameter lists in object/class bodies, with negative method writes and valid outer-resumption fixtures. The 316-test combined suite passes and `git diff --check` is clean. This remains a heuristic candidate, not JavaScript AST binding proof; unmodeled syntax and dynamic aliases require manual inspection. Independent final-tip review pending.

- Approval review of `0753896` found two method-scanner regressions: empty `function render()` params raised a `TypeError` and `if(s)` was misread as an object method, hiding a valid script-alias site. Corrected empty-group handling and control-keyword exclusion; both fixtures plus empty object method now pass. Combined suite: 316 passed, `git diff --check` clean. No beta integration before a fresh approval.

## Risks / deferred

- Static signatures cannot prove an attacker-controlled source, CSP behavior, browser execution, or dynamic computed-property value. Bound regex complexity and output volume on minified bundles. Preserve source-map truncation indicators and original module provenance.

## Resume

Reconcile research packets into a finite signature matrix, implement per-site evidence and source-map-module pass, test positive/negative/offline integration, document scope and sources, checkpoint, independent review, then decide beta integration. Do not present category count as individual execution sites again.
