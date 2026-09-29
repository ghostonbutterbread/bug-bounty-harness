# Business logic skill integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `feat/business-logic-skill`
- **Base commit:** `84da40e61da0b6e841cd69ee223f4f9f636a0af3`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-29
- **Owning feature branch/ref:** `feat/business-logic-skill`
- **Latest immutable recovery checkpoint:** `8cf0239a2d7e63c7c22a5aab5c920d3cdfc5b017`
- **Feature implementation commit(s):** `8cf0239a2d7e63c7c22a5aab5c920d3cdfc5b017`
- **Inspiration / canonical references:** OWASP WSTG Business Logic, OWASP Business Logic Security Cheat Sheet, PortSwigger Web Security Academy Business Logic; AI Policies `business-logic-modeling`.

## Intent

Give BBH agents a hunt-specific entry skill and issue-family reference for understanding intended application use before classifying business-logic anomalies. Keep universal safety and intent framing in AI Policies; do not duplicate live permissions or class mechanics.

## Implemented contract

`/business-logic` routes a current scoped workflow to normal-use mapping, role/artifact/lifecycle hypothesis, owned server-side discriminator, and specialist testing; a cold reference provides issue families and a sanitized D16 lesson. The `/js` business-logic lens routes concrete leads to the skill. No live requests or credential values are involved.

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_business_logic_skill.py agents/test_js_analyzer.py agents/test_access_control_control_harness.py` (29 passed); `git diff --check` passed.
- Independent review: initial two findings (stale dossier and overlapping attacker-advantage owner) corrected in `455fcd6`; narrow re-review confirmed both resolved, no new blocker, 29 focused tests passed.
- Replay/cohort/fixture evidence: not applicable; documentation/skill route only.
- Merge/ancestry evidence: fetched `origin/beta` at `84da40e`; feature ahead by two commits and beta ahead by zero before integration.

## Blockers and deferred work

None known. The AI Policies broad business-model lens remains canonical and the BBH skill references it.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/business-logic-skill`
- **Latest immutable recovery checkpoint:** `8cf0239a2d7e63c7c22a5aab5c920d3cdfc5b017`
- **Feature implementation commit(s):** `8cf0239a2d7e63c7c22a5aab5c920d3cdfc5b017`
- **Exact resume point:** integrate reviewed feature into clean beta, omit this temporary dossier from beta, run checks and push beta.
- **Working-tree state at handoff:** clean after this decision-record commit.

## Decision gates

- **Integration gate:** targeted validation and independent review; no contradictory safety or impact doctrine.
- **Activation / cohort gate:** sync only the new BBH skill and verify load from beta.
- **Promotion gate:** no main promotion without explicit direction.

## Decision record

- 2026-09-29 — created from beta; researched business-logic categories, drafted and tested BBH skill.
- 2026-09-29 — committed implementation `8cf0239`; review found two narrow issues; corrected ownership wording and this handoff record.
- 2026-09-29 — re-review accepted corrections; fetched beta unchanged; approved for beta integration, excluding this branch-only dossier. No main promotion.
