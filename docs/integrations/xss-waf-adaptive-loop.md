# Adaptive XSS/WAF workflow integration dossier

- **Status:** feature
- **Owner:** Hermes Agent (Ryushe request)
- **Branch / owning ref:** `docs/xss-waf-adaptive-loop`
- **Base commit:** `4b0fb836dd2622523c03640297cbe98416b50f3a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Latest immutable recovery checkpoint:** `50354c35c221a00bdadb07abff0a2892e4f38d92`
- **Feature implementation commits:** `15a38ce9a15adb5ae3b0c1a6de1608629cd3bdb2`, `50354c35c221a00bdadb07abff0a2892e4f38d92`
- **Inspiration:** Discord thread 1557545732226031677, request 1557824476916359200; Hoster Hollister XSS handoff read-only; existing BBH XSS/WAF policy and ResearchMap/MapStore contracts.

## Intent and success criteria

Teach an adaptive loop rather than a payload bank: clean baseline and one-variable differential; classify the actual control; retrieve scoped application facts and matching portable WAF/parser cards; decide whether evidence suffices to build a plausible bypass of that control which retains an executable consumer; if thin, perform focused source research; construct/test a context-matched candidate with a negative control; record distinct pass/origin/render/browser/delivery outcomes and retain negative/residual questions; promote reviewed portable findings to ResearchMap and target facts to MapStore. The WAF skill owns the general loop, an XSS-specific loadable overlay owns candidate semantics. Vendor specificity lives in on-demand cards/source references. Do not change live-testing safety policy, data schemas, script execution, or target evidence.

## Implemented contract

The general `waf` skill now leads with a measured baseline, control-location,
scoped MapStore/ResearchMap retrieval, sufficiency-for-a-plausible-bypass,
focused research when thin, one-variable candidate comparison, class-specific
proof, and reviewed learning. A first independent review identified that the
existing bypass harness and interceptor fan out over nested retries whose inner
requests are not all `--rps`-governed. This branch now gates those automatic
paths out of narrow live WAF/XSS probes without claiming to repair runtime
pacing; their counters are not exploit proof. The linked WAF playbook now agrees
on proof and Attempts/MapStore ownership. New loadable
`skills/xss-waf-evasion/SKILL.md` connects that loop to XSS sink grammar,
four proof gates and victim-transport limits; two on-demand references contain a
conditional technique-question matrix and 46 source links without copied payload
corpora. `skills/xss` and `skills/xss-payload-engineering` route a warm/hot
filter signal to it. No live-target probe, data schema or runtime code changed.

## Evidence and review

- Focused XSS suite: beta checkout's pinned `.venv/bin/python -m pytest agents/test_xss_*.py -q` from this worktree, 147 passed at first review; `agents` imported from this feature worktree and installed Bounty Core commit matched the manifest pin `54ac5e8`.
- Corrected focused WAF/XSS/routing/adoption suite: `PYTHONPATH="$PWD" /home/ryushe/projects/bug_bounty_harness/bbh-beta-integration/.venv/bin/python -m pytest tests/test_waf_interceptor.py agents/test_xss_*.py agents/test_agent_context_routing.py agents/test_shared_skill_adoption.py -q`, 157 passed.
- New WAF/XSS contract checks: five tests in `agents/test_xss_waf_adaptive_skill.py`, included in the 157; cover tool pacing guidance, playbook claim/record boundaries, unknown vendor cards and parser reference resolution.
- Baseline note: one pre-existing `test_xss_skill_clarity.py` assertion failed on clean beta because the router said “input or consumer and render context”; this branch's equivalent wording restores the tested phrase while preserving sink-first discovery, and the full XSS suite passes.
- Frontmatter/reference validation: YAML loaded and both linked references exist; 46 unique source links; `git diff --check` clean.
- Independent first review of `4b0fb83..029f923`: blocked on broad harness guidance (P1), playbook proof/record drift (P2), unknown-vendor card wording (P2), and a cross-skill reference (P3). Corrected in this feature branch; independent re-review of the corrected commit pending.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

The automatic interceptor's nested retry pacing is not repaired by this skill
change. Its live use as a narrow comparison remains gated until selection and
aggregate rate governance are implemented and tested in a separately scoped
tool change. Live target testing is out of scope and not an integration gate.
New vendor-specific ResearchMap cards require their own evidence and review
when a qualifying mechanism is observed; this branch does not seed unverified
target claims.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-waf-adaptive-loop`
- **Latest immutable recovery checkpoint:** `50354c35c221a00bdadb07abff0a2892e4f38d92`
- **Feature implementation commits:** `15a38ce9a15adb5ae3b0c1a6de1608629cd3bdb2`, `50354c35c221a00bdadb07abff0a2892e4f38d92`
- **Exact resume point:** obtain fresh independent review of the corrected range against base `4b0fb83`, then integrate into beta only if blockers are cleared.
- **Working-tree state at handoff:** clean after dossier-only handoff commit; the branch tip includes this later dossier update.

## Decision gates

- **Integration gate:** focused and relevant XSS tests, independent review, clean beta merge check, no conflicting skill owners.
- **Activation gate:** beta push followed by runtime symlink/readback verification; no Hoster mutation unless separately needed and safe.
- **Promotion gate:** stable/main only on explicit user direction.

## Decision record

- 2026-10-08 — isolated feature from fetched beta; outlined boundaries before editing skill owners.
- 2026-10-08 — implemented and exercised adaptive skill workflow; focused XSS suite 147 passed; implementation checkpoint `15a38ce9a15adb5ae3b0c1a6de1608629cd3bdb2` awaits independent review.
- 2026-10-08 — first review blocked unsafe harness recommendation and playbook proof drift; removed live automatic-retry recipe, aligned proof/record ownership and references, added regressions; corrected focused suite 157 passed; re-review pending.
- 2026-10-08 — corrected implementation checkpoint `50354c35c221a00bdadb07abff0a2892e4f38d92` ready for independent re-review.
