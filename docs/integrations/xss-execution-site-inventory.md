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

## Risks / deferred

- Static signatures cannot prove an attacker-controlled source, CSP behavior, browser execution, or dynamic computed-property value. Bound regex complexity and output volume on minified bundles. Preserve source-map truncation indicators and original module provenance.

## Resume

Reconcile research packets into a finite signature matrix, implement per-site evidence and source-map-module pass, test positive/negative/offline integration, document scope and sources, checkpoint, independent review, then decide beta integration. Do not present category count as individual execution sites again.
