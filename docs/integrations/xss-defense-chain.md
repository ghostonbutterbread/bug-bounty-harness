# XSS defense-chain integration dossier

- **Status:** review-ready
- **Owner:** Hermes bugfix profile
- **Branch:** `docs/xss-defense-chain`
- **Base commit:** `2c469eb07e37d8ffffdabf36e87f607220e6aba3`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-14
- **Owning feature branch/ref:** `docs/xss-defense-chain`
- **Latest immutable recovery checkpoint:** `b71e3be7989c5a3d288919c683ea86551765484f`
- **Feature implementation commit(s):** `b71e3be7989c5a3d288919c683ea86551765484f`
- **Inspiration / canonical references:** Ryushe's Discord request; `skills/xss/SKILL.md`, `skills/xss-payload-engineering/SKILL.md`, `skills/waf/SKILL.md`, `skills/xss-lifecycle/SKILL.md`

## Intent

Turn credible source-to-sink XSS discovery into defense-chain investigation: locate the first observed blocker and follow the value across layers and later consumers, rather than pivoting to another easy input after a sanitizer, WAF, or CSP signal. Preserve existing scope, rate, ownership, cleanup, recording and execution-proof contracts. No fixed bypass hierarchy or guarantee of XSS.

## Implemented contract

`skills/xss/SKILL.md` now routes warm paths through an observed first blocker,
including CSP and later-consumer branches, to the canonical conditional
`references/defense-chain.md`. That reference differentiates WAF, sanitizer,
CSP, and later renderers; it preserves the existing XSS lane's proof standard,
Attempts ownership and program safety constraints. No fixed bypass hierarchy,
payload cap, or guaranteed-XSS claim.

## Evidence and review

- Tests and commands: `uv run --with pytest python -m pytest agents/test_xss_defense_chain_policy.py agents/test_xss_defense_signal_routing.py agents/test_xss_skill_clarity.py agents/test_xss_waf_adaptive_skill.py -q` (17 passed); `git diff --check` passed.
- Independent review: read-only reviewer approved XSS guidance and its route/proof ownership; requested this dossier's recovery-state correction before integration.
- Replay/cohort/fixture evidence: prose policy; no live target test planned.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- None known. Runtime activation follows reviewed beta integration and managed projection verification.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-defense-chain`
- **Latest immutable recovery checkpoint:** `b71e3be7989c5a3d288919c683ea86551765484f`
- **Feature implementation commit(s):** `b71e3be7989c5a3d288919c683ea86551765484f`
- **Exact resume point:** Verify this dossier-only correction, then integrate into the current `beta` worktree; remove this temporary dossier from the integration target.
- **Working-tree state at handoff:** clean after the dossier-correction commit.

## Decision gates

- **Integration gate:** focused regressions, router/reference resolution, independent review and clean merge.
- **Activation / cohort gate:** selected beta source and managed skill projection resolve the new content; no live hunt implied.
- **Promotion gate:** main only on explicit request.

## Decision record

- 2026-10-14 — created from fetched `origin/beta`, independent of a stale review card whose artifact is absent.
- 2026-10-14 — reviewer approved guidance with a blocking dossier-state correction; corrected the handoff and retained the implementation checkpoint.
