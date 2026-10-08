# Adaptive XSS/WAF workflow integration dossier

- **Status:** feature
- **Owner:** Hermes Agent (Ryushe request)
- **Branch / owning ref:** `docs/xss-waf-adaptive-loop`
- **Base commit:** `4b0fb836dd2622523c03640297cbe98416b50f3a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Inspiration:** Discord thread 1557545732226031677, request 1557824476916359200; Hoster Hollister XSS handoff read-only; existing BBH XSS/WAF policy and ResearchMap/MapStore contracts.

## Intent and success criteria

Teach an adaptive loop rather than a payload bank: clean baseline and one-variable differential; classify the actual control; retrieve scoped application facts and matching portable WAF/parser cards; decide whether evidence suffices to build a plausible bypass of that control which retains an executable consumer; if thin, perform focused source research; construct/test a context-matched candidate with a negative control; record distinct pass/origin/render/browser/delivery outcomes and retain negative/residual questions; promote reviewed portable findings to ResearchMap and target facts to MapStore. The WAF skill owns the general loop, an XSS-specific loadable overlay owns candidate semantics. Vendor specificity lives in on-demand cards/source references. Do not change live-testing safety policy, data schemas, script execution, or target evidence.

## Implemented contract

The general `waf` skill now leads with a measured baseline, control-location,
scoped MapStore/ResearchMap retrieval, sufficiency-for-a-plausible-bypass,
focused research when thin, one-variable candidate comparison, class-specific
proof, and reviewed learning. The existing interceptor remains optional mechanics
and its counters are not exploit proof. New loadable
`skills/xss-waf-evasion/SKILL.md` connects that loop to XSS sink grammar,
four proof gates and victim-transport limits; two on-demand references contain a
conditional technique-question matrix and 46 source links without copied payload
corpora. `skills/xss` and `skills/xss-payload-engineering` route a warm/hot
filter signal to it. No live-target probe, data schema or runtime code changed.

## Evidence and review

- Focused XSS suite: beta checkout's pinned `.venv/bin/python -m pytest agents/test_xss_*.py -q` from this worktree, 147 passed; `agents` imported from this feature worktree and installed Bounty Core commit matched the manifest pin `54ac5e8`.
- New WAF/XSS contract checks: three tests in `agents/test_xss_waf_adaptive_skill.py`, included in the 147.
- Baseline note: one pre-existing `test_xss_skill_clarity.py` assertion failed on clean beta because the router said “input or consumer and render context”; this branch's equivalent wording restores the tested phrase while preserving sink-first discovery, and the full XSS suite passes.
- Frontmatter/reference validation: YAML loaded and both linked references exist; 46 unique source links; `git diff --check` clean.
- Independent review: pending.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

None identified. Live target testing is out of scope and not an integration gate. New vendor-specific ResearchMap cards require their own evidence and review when a qualifying mechanism is observed; this branch does not seed unverified target claims.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-waf-adaptive-loop`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Exact resume point:** author skill content and focused tests, run checks, commit, independently review, then integrate into beta.
- **Working-tree state at handoff:** intentionally uncommitted draft (this dossier).

## Decision gates

- **Integration gate:** focused and relevant XSS tests, independent review, clean beta merge check, no conflicting skill owners.
- **Activation gate:** beta push followed by runtime symlink/readback verification; no Hoster mutation unless separately needed and safe.
- **Promotion gate:** stable/main only on explicit user direction.

## Decision record

- 2026-10-08 — isolated feature from fetched beta; outlined boundaries before editing skill owners.
