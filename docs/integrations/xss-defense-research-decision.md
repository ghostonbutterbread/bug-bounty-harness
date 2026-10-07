# XSS defense/research decision integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/xss-defense-research-decision`
- **Base commit:** `f4196f7b0798cbddad390b585466fa4843ab0ad2` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `docs/xss-defense-research-decision`
- **Latest immutable recovery checkpoint:** `d11150c393e417ee84d974e5281d1e085c20c2f9`
- **Feature implementation commit(s):** `d11150c393e417ee84d974e5281d1e085c20c2f9`
- **Inspiration / canonical references:** Hollister XSS Herdr review; `skills/xss/SKILL.md` defense-signal routing and `skills/xss-technology-research/SKILL.md`.

## Intent

Break repeated probe/block/probe tunnel vision without making research a hard prerequisite or curtailing creative WAF testing. Patch only the canonical XSS router's defense-signal decision aid.

## Implemented contract

At similar resistance to distinct probes, consider whether observed stack, response differences, and prior notes can change the next discriminator. Route a concrete research question to existing XSS technology research when useful; otherwise continue distinct context-matched probing. A filter pass is not execution proof and vendor certainty is not a gate.

## Evidence and review

- Tests and commands: `git diff --check`; `python3 -m pytest tests/test_script_policy.py tests/test_goal_router.py -q` (31 passed); AI Policies `python3 scripts/policy_lint.py` (passed; structural neighboring-policy lint, not a substitute for BBH review).
- Independent review: read-only review of `d11150c` found no policy issue; one low-severity stale dossier receipt corrected here. Reviewer reran 31 focused tests and `git diff --check origin/beta...d11150c`.
- Replay/cohort/fixture evidence: policy-only change; Hollister transcript supplied the failure mode, not a live-target retest.
- Merge/ancestry evidence: branch starts at fetched `origin/beta` f4196f7.
- Policy-alignment neighbors: general/live-testing baseline, `waf-live-policy`, `xss-payload-engineering`, `xss-technology-research`, XSS research-card reference. Compatible guidance; no parallel operational owner.

## Blockers and deferred work

- None known. A runtime agent exercise would be useful after beta publication but is not a substitute for a reviewed policy diff.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-defense-research-decision`
- **Latest immutable recovery checkpoint:** `d11150c393e417ee84d974e5281d1e085c20c2f9`
- **Feature implementation commit(s):** `d11150c393e417ee84d974e5281d1e085c20c2f9`
- **Exact resume point:** Reconcile beta, remove this temporary dossier during integration, verify and publish beta.
- **Working-tree state at handoff:** clean after this dossier-only commit.

## Decision gates

- **Integration gate:** focused checks, policy alignment and independent review; clean beta reconciliation.
- **Activation / cohort gate:** separate Hoster beta skill projection and fresh consumer read if runtime activation requested.
- **Promotion gate:** stable/main promotion requires explicit operator request.

## Decision record

- 2026-10-07 — Created a narrow XSS router decision aid on a feature branch.
- 2026-10-07 — Independent review accepted the policy text; corrected the handoff receipt before integration.
