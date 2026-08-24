---
name: manual-places-to-hunt
description: Use after a meaningful hunt segment or handoff to rank current-run evidence into a compact, read-only manual inspection queue.
---

# Manual Surface Review

Use when asked what deserves manual attention from the current hunt segment:

```text
/manual <program> [--run <run-id>] [--historical]
```

This is an evidence-synthesis skill, not a live-testing lane. By default it is
read-only and regenerates its queue from canonical evidence. It does not create
a separate manual-findings database or silently reopen historical leads.

## Review Boundary

1. Resolve the program, run ID, objective, lane, and explicit exclusions.
2. Review current-run Attempts, reports, handoffs, sidecar results, and
   subagent packets first.
3. Query MapStore only for concrete URLs, parameters, sinks, or trust boundaries
   already observed in this run (`app-facts`, `dedupe`, or `coverage` intent).
4. Include unresolved missing-artifact blockers where a bounded human action
   could obtain the discriminator.
5. Do not pull broad historical leads unless `--historical`, a retest, or a
   repass is explicitly requested.
6. Never recommend a surface that violates an active scope, account, safety, or
   user exclusion. Treat exclusions as request-scoped unless explicitly made
   standing policy.

Canonical owners remain unchanged:

- Attempts own exact probes, payloads, transformations, and outcomes;
- MapStore owns stable observed facts and narrow tested-state conclusions;
- Hypothesis Ledger owns unfinished private branches and wake conditions;
- Bounty Notes owns human decisions and handoffs;
- reports and sidecars own their generated evidence.

Persist only what belongs to those owners. If the user asks to save this view,
write a concise run-scoped handoff such as
`_runs/<run-id>/handoffs/manual-surfaces.md`; regenerate the ranking after
material evidence changes.

## Candidate Threshold

Include a surface only when a material signal exists, for example:

- controlled input reflects, persists, reaches the DOM, or affects a UI error;
- input reaches a parser, raw HTML, URL, script, style, template, native bridge,
  or later consumer;
- a sanitizer, encoder, WAF, CSP, framework helper, or parser boundary was
  observed;
- a UI-only workflow, role, browser state, CAPTCHA, or physical integration is
  the one remaining discriminator;
- one missing response, route snapshot, chunk, producer, or API contract blocks
  closure; or
- a subagent has a concrete source-to-sink chain whose final reachability
  question is best answered manually.

Exclude generic fingerprints, cold parameter inventories with no consumer,
fully explained equivalent mutations, scope-uncertain third-party surfaces, and
unbounded “try more payloads” suggestions.

## Rank for Information Gain

Rank by expected information gain and distance to meaningful impact, not payload
count or novelty. Prefer, in order:

1. proven attacker control;
2. proximity to an executable or high-capability sink;
3. transformations already understood;
4. one exact unknown rather than several speculative prerequisites;
5. manual/browser/account context that uniquely resolves that unknown;
6. victim reach, persistence, cross-user delivery, or privileged-consumer
   potential;
7. program fit, safety, ownership, cleanup, freshness, and coverage state.

Use these tiers narrowly:

- **Push now** — proven source plus a dangerous sink or strong parser boundary;
  one bounded manual discriminator remains.
- **Inspect manually** — browser-only rendering or a promising transform is
  visible, but escaping or a control is still likely.
- **Acquire evidence** — a missing route chunk, response, role page, or consumer
  must be captured before a useful test.
- **Hold** — a residual is interesting but lacks attacker control, a prerequisite,
  or a permitted next step.

Do not call a candidate vulnerable without proven execution and impact. A narrow
safe consumer is not a host-wide defense conclusion.

## Manual Action Cards

Lead with one to three items and keep each card immediately actionable:

```text
Rank and tier: <1 — Push now>
Surface: <host/path/feature>
Input: <field, parameter, stored value, hash, or API field>
Signal: <observed behavior>
Proven chain: <source -> transforms -> consumer/sink>
Unknown: <one exact unresolved question>
Manual action: <smallest bounded discriminator>
Expected observation: <what success and failure look like>
Stop/cleanup: <scope, challenge, state, residue, or interaction boundary>
Evidence: <Attempt IDs and artifact/report/MapStore pointers>
Why ranked here: <one sentence>
```

Then summarize notable reflections and parser boundaries, missing artifacts that
would unlock a hot branch, excluded surfaces and why, and whether the queue is
current-run-only or historical.

Use inert markers and DOM/network inspection when execution is not yet justified.
If an item needs a live action, present the action first; perform it only after
the user requests it and the normal live/account/payment/social/device policies
allow it. Do not expose cookies, tokens, OAuth state, private object IDs, or
sensitive response bodies in cards or handoffs.

## Completion Check

Before returning the queue, verify that every recommendation is tied to observed
evidence, names one exact unknown and discriminator, respects the active
boundaries, links to current artifacts, and makes the highest-ranked item the
best manual use of time.
