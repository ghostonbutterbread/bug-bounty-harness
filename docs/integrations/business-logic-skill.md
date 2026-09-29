# Business logic skill integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `feat/business-logic-skill`
- **Base commit:** `84da40e61da0b6e841cd69ee223f4f9f636a0af3`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-29
- **Owning feature branch/ref:** `feat/business-logic-skill`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** OWASP WSTG Business Logic, OWASP Business Logic Security Cheat Sheet, PortSwigger Web Security Academy Business Logic; AI Policies `business-logic-modeling`.

## Intent

Give BBH agents a hunt-specific entry skill and issue-family reference for understanding intended application use before classifying business-logic anomalies. Keep universal safety and intent framing in AI Policies; do not duplicate live permissions or class mechanics.

## Implemented contract

`/business-logic` routes a current scoped workflow to normal-use mapping, role/artifact/lifecycle hypothesis, owned server-side discriminator, and specialist testing; a cold reference provides issue families and a sanitized D16 lesson. The `/js` business-logic lens routes concrete leads to the skill. No live requests or credential values are involved.

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_business_logic_skill.py agents/test_js_analyzer.py agents/test_access_control_control_harness.py` (29 passed); `git diff --check` passed.
- Independent review: pending.
- Replay/cohort/fixture evidence: not applicable; documentation/skill route only.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

None known. The AI Policies broad business-model lens remains canonical and the BBH skill references it.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/business-logic-skill`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** independent review, reconcile beta tip, then integrate to beta.
- **Working-tree state at handoff:** intentionally uncommitted draft.

## Decision gates

- **Integration gate:** targeted validation and independent review; no contradictory safety or impact doctrine.
- **Activation / cohort gate:** sync only the new BBH skill and verify load from beta.
- **Promotion gate:** no main promotion without explicit direction.

## Decision record

- 2026-09-29 — created from beta; researched business-logic categories, drafted and tested BBH skill.
