# XSS defense/research decision integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `docs/xss-defense-research-decision`
- **Base commit:** `f4196f7b0798cbddad390b585466fa4843ab0ad2` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `docs/xss-defense-research-decision`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Hollister XSS Herdr review; `skills/xss/SKILL.md` defense-signal routing and `skills/xss-technology-research/SKILL.md`.

## Intent

Break repeated probe/block/probe tunnel vision without making research a hard prerequisite or curtailing creative WAF testing. Patch only the canonical XSS router's defense-signal decision aid.

## Implemented contract

At similar resistance to distinct probes, consider whether observed stack, response differences, and prior notes can change the next discriminator. Route a concrete research question to existing XSS technology research when useful; otherwise continue distinct context-matched probing. A filter pass is not execution proof and vendor certainty is not a gate.

## Evidence and review

- Tests and commands: `git diff --check`; `python3 -m pytest tests/test_script_policy.py tests/test_goal_router.py -q` (31 passed); AI Policies `python3 scripts/policy_lint.py` (passed; structural neighboring-policy lint, not a substitute for BBH review).
- Independent review: pending.
- Replay/cohort/fixture evidence: policy-only change; Hollister transcript supplied the failure mode, not a live-target retest.
- Merge/ancestry evidence: branch starts at fetched `origin/beta` f4196f7.
- Policy-alignment neighbors: general/live-testing baseline, `waf-live-policy`, `xss-payload-engineering`, `xss-technology-research`, XSS research-card reference. Compatible guidance; no parallel operational owner.

## Blockers and deferred work

- None known. A runtime agent exercise would be useful after beta publication but is not a substitute for a reviewed policy diff.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-defense-research-decision`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** Run checks, independent review, then commit and integrate if clean.
- **Working-tree state at handoff:** intentionally uncommitted pending verification.

## Decision gates

- **Integration gate:** focused checks, policy alignment and independent review; clean beta reconciliation.
- **Activation / cohort gate:** separate Hoster beta skill projection and fresh consumer read if runtime activation requested.
- **Promotion gate:** stable/main promotion requires explicit operator request.

## Decision record

- 2026-10-07 — Created a narrow XSS router decision aid on a feature branch.
