# XSS consumer reach integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch / owning ref:** `docs/xss-consumer-reach`
- **Base commit:** `91f000b` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-21
- **Latest immutable recovery checkpoint:** `ecf23ca448d7cc2827ec70170e514d6594aa140c`
- **Feature implementation commits:** `ecf23ca448d7cc2827ec70170e514d6594aa140c`
- **Inspiration:** `~/Shared/skill_seeds/2026-10-21-xss-consumer-reach.md`

## Intent and implemented contract

Classify an absent XSS render consumer before labeling a non-fire a sanitizer negative or exhaustion. The existing `xss` router conditionally loads `references/consumer-reach.md`; mounted value changes still use the defense chain and selected lane for proof. The reference distinguishes reachability, defense, policy, and separate ingress paths; it routes client-gate claims to `assumption-testing`, owned setup to `account-testing-policy`, human challenges to `captcha-policy`, and external unremediable prerequisites to `blockers`. It does not grant new target authorization or add a payload pack.

## Evidence and review

- Focused: `python3 -m pytest -q tests/test_xss_consumer_reach.py tests/test_xss_mechanism_ideation.py agents/test_xss_defense_chain_policy.py agents/test_xss_skill_clarity.py` — 12 passed.
- `git diff --check` — clean.
- Alignment checked against `xss` router, `source-acquisition`, `defense-chain`, `xss-lifecycle`, `assumption-testing`, `account-testing-policy`, `captcha-policy`, and `blockers`.
- Independent read-only review approved with no blocking findings; reviewer reran 12 focused tests and `git diff --check`. Parent reran the 12 focused tests after review (12 passed).
- Root `python3 -m pytest -q` cannot collect `test_catalog.py` (`bac_checks` absent in this checkout); `python3 -m pytest -q tests agents` exceeded tool's 420-second limit without a receipt. Expanded focused group: 46 passed, 1 unrelated existing script-index failure (`stack-to-program/scripts/README.md` lacks Outputs/Mutates); 12 direct XSS tests passed. No claim of full-suite green.

## Blockers and deferred work

Full suite green is unavailable in this checkout for the unrelated collection and script-index issues above; these are not waived as passing tests. No live target probing is required for this policy-text change. Beta activation and fresh consumer load remain pending integration and verification.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-consumer-reach`
- **Latest immutable recovery checkpoint:** `ecf23ca448d7cc2827ec70170e514d6594aa140c` (reviewed implementation).
- **Feature implementation commit(s):** `ecf23ca448d7cc2827ec70170e514d6594aa140c`.
- **Exact resume point:** merge reviewed feature into current beta, remove this temporary dossier, run integrated focused tests, verify projection.
- **Working-tree state at handoff:** clean after dossier decision commit.

## Decision gates

- **Integration:** alignment, independent review, focused XSS tests, current beta and clean integration tree; disclose unrelated full-suite failures above.
- **Activation:** selected source and active skill link resolve updated router/reference.
- **Promotion:** no stable promotion requested.

## Decision record

- 2026-10-21 — feature drafted from reviewed seed with path-scoped evidence and ownership refinements.
- 2026-10-21 — independent review accepted; focused tests green, full-suite limitations recorded; integrate to beta without claiming global green.
