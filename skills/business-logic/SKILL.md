---
name: business-logic
description: "Use when hunting workflow, role, value, state, or lifecycle flaws by comparing actual application behavior with its intended business operation."
---

# Business Logic Hunting

**Owner:** BBH's hunt route from an application's normal operation to a distinct misuse hypothesis and owned proof. Load `general-security-testing-policy` first; before live actions, load `live-testing-policy`. Load `business-logic-modeling` for the business-purpose, owner-expectation, and lifecycle interpretation; `impact-fit-policy` owns incremental attacker advantage and consequence. This skill does not replace those decisions or class-specific mechanics.

## Start with the normal use

Browser-drive the feature's normal UI with `/live-map` and `/chromium-test` before claiming to understand or exhaust it. Read product/developer docs with `/docs` when they clarify roles or operations; map requests and effects through `/analyze-endpoint` or task MITM as useful. Begin with a current scoped surface rather than treating prior leads as proof. Identify the actors, artifact/value, role permissions, expected sequence, state transitions, ownership, visibility/audit trail, and lifecycle end. Record what is *observed* separately from what is inferred to be intended.

Before forming an abuse idea, ask: **What are my account's normal permissions?
Is this action on this resource already allowed for me, or would the proposed
abuse grant access I do not normally have?**

Then ask what the business assumes a user cannot or would not do. Compare the actor's legitimate capability with the suspected path: does it give a different artifact, hide a transfer or exposure from the owner, evade a contextual rule, alter value, or preserve a capability after a meaningful transition? A technically permitted action is not automatically harmless; a surprising UI response is not automatically a vulnerability. Load `references/business-model-and-issue-families.md` for candidate issue families and the D16 interpretation lesson, then form a specific invariant and an owned, observable discriminator. Use `/assumption-testing` for server enforcement claims and `/hypothesis-expansion-policy` for distinct candidate branches.

## Follow the consequential branch

Explore one meaningful change in actor, object, order, time/state, quantity/value, or channel at a time. Use comparable owned accounts/fixtures and the ordinary baseline; verify the resulting *server-side* effect, not just a button, status, or redirect. A negative result retires only that tested link. If the business rule remains ambiguous, seek documentation, another owned role/flow, audit visibility, or a safe downstream consumer check rather than assert intent. Preserve observed facts with `/map-store`, private hypotheses with `/hypothesis-ledger`, exact probes in Attempts, and validated findings with `/findings` promptly; keep secrets out of those records.

Route authorization and credential ownership to `/access-control` or `/idor` plus `idor-live-policy`; one-time workflow interception to `/single-request-grabber`; payment and rewards to `payment-testing-policy`; race/TOCTOU to `race-live-policy`; request-shape mutations to `/request-exploration`. Follow `account-testing-policy` for owned setup. Published program rules, scope, rate, ownership, sensitive-data, financial, public/staff-facing, and destructive-effect boundaries remain controlling; this skill grants no extra live permission.
