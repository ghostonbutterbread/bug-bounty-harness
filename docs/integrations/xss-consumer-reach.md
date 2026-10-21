# XSS consumer reach integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch / owning ref:** `docs/xss-consumer-reach`
- **Base commit:** `91f000b` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-21
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Inspiration:** `~/Shared/skill_seeds/2026-10-21-xss-consumer-reach.md`

## Intent and implemented contract

Classify an absent XSS render consumer before labeling a non-fire a sanitizer negative or exhaustion. The existing `xss` router conditionally loads `references/consumer-reach.md`; mounted value changes still use the defense chain and selected lane for proof. The reference distinguishes reachability, defense, policy, and separate ingress paths; it routes client-gate claims to `assumption-testing`, owned setup to `account-testing-policy`, human challenges to `captcha-policy`, and external unremediable prerequisites to `blockers`. It does not grant new target authorization or add a payload pack.

## Evidence and review

- Focused: `python3 -m pytest -q tests/test_xss_consumer_reach.py tests/test_xss_mechanism_ideation.py agents/test_xss_defense_chain_policy.py agents/test_xss_skill_clarity.py` — 12 passed.
- `git diff --check` — clean.
- Alignment checked against `xss` router, `source-acquisition`, `defense-chain`, `xss-lifecycle`, `assumption-testing`, `account-testing-policy`, `captcha-policy`, and `blockers`.
- Independent review: pending.
- Root `python3 -m pytest -q` cannot collect `test_catalog.py` (`bac_checks` absent in this checkout); `python3 -m pytest -q tests agents` exceeded tool's 420-second limit without a receipt. Expanded focused group: 46 passed, 1 unrelated existing script-index failure (`stack-to-program/scripts/README.md` lacks Outputs/Mutates); 12 direct XSS tests passed. No claim of full-suite green.

## Blockers and deferred work

None known. No live target probing is required for this policy-text change. Beta activation and fresh consumer load remain pending integration and verification.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-consumer-reach`
- **Latest immutable recovery checkpoint:** none yet; commit after full verification.
- **Feature implementation commit(s):** none yet.
- **Exact resume point:** run full suite, independent review, commit and integrate into current beta.
- **Working-tree state at handoff:** intentionally uncommitted until verification.

## Decision gates

- **Integration:** full suite, alignment, independent review, current beta and clean integration tree.
- **Activation:** selected source and active skill link resolve updated router/reference.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-10-21 — feature drafted from reviewed seed with path-scoped evidence and ownership refinements.
