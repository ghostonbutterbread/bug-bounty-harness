---
name: form-submission-testing
description: "Use when filling an authorized web form for testing."
version: 0.1.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, web, forms, validation, testing]
    related_skills: [general-security-testing-policy, live-testing-policy, intercepted-proxy]
---

# Form Submission Testing

Complete and test authorized forms without mistaking a disabled button, validation error, or hidden dependency for an untestable surface. This skill governs form-state discovery and controlled input variation; scope, ownership, rate, and side-effect policy remain mandatory.

## When to Use

- A security test needs a browser form completed, submitted, or diagnosed.
- Submit is disabled, blocked, rejected, or appears to do nothing.
- Fields are conditional, optional, type-constrained, or client-validated.
- A valid browser submission will be captured and a single allowed value replayed or temporarily modified.

Do not use this to bypass CAPTCHA, consent, authorization, anti-automation, payment, human-review, or public-publishing controls.

## Prerequisites

1. Before target interaction, load `general-security-testing-policy` then `live-testing-policy`; verify scope, program rules, rate, ownership, and the concrete effect of submitting.
2. Use an owned or expressly authorized account and a suitable owned fixture. Stop or ask for staff-visible, direct-broadcast/non-owned messaging, paid, fulfillment, moderation, destructive, non-owned, or unclear-impact submissions. A form editing an owned public profile/post is not approval-gated by visibility alone; route direct-impact support/community forms through `public-forums`, owned social posts through `account-testing-policy` + `public-artifacts`, and checkout through `payment-testing-policy`. This skill does not grant permission to submit.
3. For a browser/stateful flow, use the browser policy chain. For capture, replay, or live mutation, also load `proxy-routing-policy` and `intercepted-proxy`; for a suspected input/filter issue, load `injection-testing-policy`.

## Procedure

1. **Map the baseline state.** Read labels, help text, required indicators, placeholders, accepted formats, inline errors, native validation messages, accessibility names, and submit-control state. Completion: every visible field and stated dependency is classified as mandatory, optional, conditional, read-only, or unknown.
2. **Find conditional prerequisites.** Exercise one low-impact controller at a time—such as a dropdown, radio group, checkbox, country, account type, or toggle—and re-check the visible fields and validity state. Completion: controlling values and the fields they reveal, require, disable, or clear are recorded.
3. **Classify the blocker.** Determine whether the constraint is missing/invalid baseline data, a type/format rule, a conditional requirement, an account/authorization state, rate limit, CAPTCHA, or an approval boundary. Completion: the reason is grounded in a message, observed state transition, or response; do not infer it from a disabled control alone.
4. **Create a minimal valid baseline.** Fill mandatory fields with valid, disposable owned test data appropriate to their declared type. Examples: use a structurally valid test address only where it has no delivery, identity, tax, credit, or other external consequence. Completion: one permitted baseline submission succeeds, or the remaining blocker is explicitly classified.
5. **Cover optional and alternate branches.** For each meaningful optional field or controller, compare omission with an allowed valid value; test alternate dropdown/radio choices that materially change validation, fields, routing, or request shape. Completion: every meaningful visible branch is either compared, excluded with a scoped reason, or deferred at an approval boundary.
6. **Vary one meaningful input at a time.** Starting from the baseline, test one permitted boundary or malformed representation at a time—such as a declared address component, length boundary, encoding, empty-versus-omitted optional field, or type mismatch—while other values stay constant. Completion: each result is attributable to the changed variable.
7. **Capture only after baseline.** When browser-generated state matters, capture one successful owned submission through the task-scoped MITM. Replay or temporarily modify only the approved request family and one variable, then observe the response and owned effect. Completion: the captured baseline, sanitized mutation, response, and cleanup are recorded; no interception rule remains.
8. **Record and continue safely.** Distinguish UI-only prevention from server validation, authorization, and durable state change. Record the required state, submitted/omitted field category, one changed variable, response class, and owned effect. Completion: the next test, pivot, ask, or stop decision follows evidence and applicable policy.

## JavaScript Lens

When `/js` observes form controllers, client validators, conditional fields,
serialization, or a submit request builder, carry a compact source/proxy packet
with module or route provenance into the form-state map. Compare it with the
visible browser state and an allowed task-MITM baseline; source code alone does
not establish server validation, authorization, or permission to submit. `/js`
owns bundle inventory; this skill owns only the controlled form workflow.

## CAPTCHA and Other Boundaries

- A CAPTCHA is a control, not a malformed field. Do not bypass it, rotate IPs, automate solving, or modify its verification values to force submission.
- Record where it appears and whether it blocks baseline or only a branch. Follow `live-testing-policy` for an approval request or stop condition.
- Never interpret a client-side disabled button as server-side protection without an allowed baseline or independently observed server behavior.

## Pitfalls

- **Bogus data with side effects:** syntactically valid filler is not automatically safe. Never fabricate a recipient, identity, payment, delivery, tax, or public-content value.
- **Combining variations:** do not change multiple fields together unless the intentional question is their interaction; otherwise results are not attributable.
- **Optional does not mean irrelevant:** optional fields and alternate selectors can alter validation, serialization, backend routing, and authorization context.
- **Replay without a baseline:** do not construct or mutate a request family before capturing a successful task-MITM baseline.
- **Stopping at the UI:** a UI error is evidence about the client. It does not establish the server invariant.

## Verification

Before calling a form blocked or covered, verify that:

- every visible mandatory and meaningful optional/conditional branch was classified;
- an allowed minimal baseline was attempted, or its blocker was evidenced and correctly escalated;
- each deliberate variation has a stable baseline and one changed variable;
- any capture/replay used a task-scoped MITM, owned state, and cleanup confirmation; and
- the record separates client validation, server validation, authorization, CAPTCHA, and approval boundaries.
