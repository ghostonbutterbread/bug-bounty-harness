---
name: blocker-first-analysis
description: "Use when a live security test is blocked or a payload fails."
version: 1.0.0
author: Hermes Agent + Ryushe
license: MIT
metadata:
  hermes:
    tags: [security-testing, reporting, blockers, evidence]
    related_skills: [blockers, bounty-notes, waf, bypass, hypothesis-expansion-policy, injection-testing-policy]
---

# Blocker-First Analysis

## When to use

Use during authorized live security testing when a mutation, payload family, or
workflow does not produce the intended effect, and when writing a test update,
handoff, pause decision, or no-finding summary. Apply scope, account, rate, and
live-testing policies first.

## Operator-facing default

Lead with the issue—not a list of payloads:

```text
BLOCKER — <narrowest evidenced condition stopping the conclusion>.
WHY — <one short causal sentence, including what this does not prove>.
NEXT — <smallest authorized check, fixture, or decision that resolves it>.
```

Keep the default update to these three short lines. Add test inventory, variant
coverage, controls, and residual paths only when they materially change the
operator's next decision. Never make the operator infer the blocker from a long
payload inventory.

## Analysis discipline

1. **Name the mechanism, not merely the result.** `Payload did not fire` is an
   observation; distinguish access/state, input acceptance, normalization or
   encoding, source-to-sink reachability, execution context, observation
   limits, and scope/policy.
2. **State the boundary of the evidence.** A failed representation rules out
   that representation on the tested path. It does not close the vulnerability
   class or an untested consumer.
3. **Check meaningful completeness before closure.** For the claimed route,
   establish the relevant preconditions and reachable variants rather than
   assuming that one response, format, context, or consumer generalizes.
4. **Keep residuals bounded.** Name only plausible untested routes that follow
   from the observed mechanism; do not turn a blocker report into speculative
   bypass ideation.
5. **Choose the smallest authorized unblock.** Prefer an observation method or
   normal workflow step where it resolves the question; use an owned fixture when
   proof would otherwise mutate non-owned state. A fixture or data sensitivity
   is not a prerequisite for in-scope disclosure testing. Where needed, use an
   owned account, role, object, or explicit scope decision over broader testing.

Use `not demonstrated under <conditions>` unless evidence closes the relevant
preconditions and meaningful reachable variants. Reserve `closed` for that
stronger conclusion.

## Continuation and research handoff

When a promising chain meets a sanitizer, validator, WAF, or CSP, characterize
which layer acts, what it changes or rejects, and what the downstream consumer
actually receives before pivoting. Compare mechanism-distinct representation,
parser, state, and consumer axes against exact Attempts; where available, consult
surface coverage for status, pressure, boundary, tested axes, evidence pointers,
and reopen conditions. Preserve *how* each axis was tried in Attempts rather than
turning payload count or a coverage status into proof of exhaustion. Pursue the
smallest plausible untested discriminator while signal, scope, and rate budget
justify it; a WAF pass alone is not execution, and CSP matters only once an
executable browser context is reached. Route WAF behavior to `waf-live-policy`
and `waf`, sanitizer/parser behavior to `injection-testing-policy` and the
applicable specialist, and concrete bypass techniques to `bypass`. Use
`hypothesis-expansion-policy` for distinct unresolved chain branches. Preserve
the tested defense and its wake condition when pivoting rather than recording a
class-wide negative. Rate limits differ: pause only the affected scope and wait
for cooldown.

For report decisions, keep *internal* prior-work lookup separate from *external*
novelty: a ledger miss cannot tell whether another researcher already reported
the issue, and a new bypass payload may still share the same root cause and fix.
Compare the demonstrated security boundary and likely required fix against any
available program known-issue or duplicate information; describe uncertainty
when the earlier report is unavailable. Defended paths are a research-priority
signal, not a guarantee of a non-duplicate report.

## Evidence and storage

`blockers` owns the optional external-prerequisite store, exact check/record/brief
commands, and remediation-first admission. This skill owns causal analysis and
the three-line decision/handoff, not a second blocker record or coverage gate.

A blocker is a first-class **optional** prerequisite record, not an Error,
Attempt, target fact, or hypothesis. It is general-purpose, not BOLA-specific.
Use it only after ordinary authorized setup has been attempted and the remaining
unblock is outside this agent's authority—for example a human-only check, an
unavailable owned role/resource, an environment repair, or a scope/policy
choice. Do not record routine setup that the agent can complete itself.

Before checking, honoring, or recording a blocker, use a **remediation-first**
pass: attempt every feasible ordinary authorized remedy, including permitted
signup/free-trial enrollment, owned account/resource or fixture creation, normal
feature setup, and bounded login/session recovery. A known blocker is never
permission to stop a runnable task. Only the remaining action that the agent
cannot physically or authoritatively perform is blocker-worthy.

When the storage surface is available, an agent may then check the exact
operation/scope for a known open blocker. If found, first assess whether the
agent can now perform its unblock condition; if so, perform it and freshly
verify the normal flow. Only if the prerequisite remains external should it
avoid repeating the specific proven dead end, preserve the concrete unblock
condition, and continue other runnable work. If no known blocker exists and the
condition remains external, write one redacted lane-scoped record with a stable
dedupe key, current run ID, blocker type, evidenced reason, non-secret
account/resource references when relevant, evidence pointer, and smallest
concrete unblock condition. An **open** record must include a sanitized
remediation-evidence reference or attestation showing which feasible authorized
remedies were attempted and why the remainder is external; reject an open record
that lacks it. Regression fixtures must use a genuinely external prerequisite,
not an owned resource the agent could create. Lifecycle remains append-only;
later resolve or supersede events never delete the original evidence. When adding run attribution
to an existing event schema, preserve legacy events in general lookup and
lifecycle derivation; exclude only events that lack attribution from per-run
briefs rather than silently dropping their history.

Do not expose blockers as a coverage verdict or completion gate. Do not make checking, recording, or reading a blocker gate mandatory for normal
testing or coverage. At completion, a run that created blockers should emit a
compact brief containing only its still-open blockers, what happened, and the
exact next action to push. This is a human revisit handoff, not an automatic
retry queue. A future agent can check the same operation/scope and avoid
spending effort on a known external limitation.

Keep the factual mechanism and reusable tested behavior in MapStore, exact
mutations in Attempts, private untested branches in the Hypothesis Ledger, and
the three-line decision/handoff in Bounty Notes. Do not copy raw credentials,
tokens, or sensitive target data into any record.

## Examples and implementation reference

See `references/blocker-first-examples.md` for compact examples and the
access/state versus defensive-mechanism distinction. See
`references/blocker-store-contract.md` for lifecycle, coverage-gate, redaction,
and Core-first adapter-integration requirements.

## Pitfalls

- Reporting every attempted payload before stating the condition that prevents a
  conclusion.
- Calling a class closed because a single payload, format, or endpoint was
  neutralized.
- Treating a missing account or workflow state as a product defense.
- Listing hypothetical bypasses that are not supported by the observed blocker.
- Omitting the authorized action or decision that would resolve uncertainty.
