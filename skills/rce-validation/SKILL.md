---
name: rce-validation
description: "Probe and validate plausible RCE primitives safely."
version: 0.2.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, rce, validation, evidence, safety]
    related_skills: [rce, rce-exploration, attempt-recording-policy]
---

# RCE Validation

Load when `rce-exploration`, `rce-surface-mapping`, or the `rce` class entry has
produced a named, plausible source-to-executor primitive question with a scoped
control point, baseline, observation channel, and stop condition. If only a
surface family or technology name is known, first clarify the chain with
`rce-exploration`. This packet supports bounded precursor probes as well as
confirmation after a signal; it is not an exploit-development or payload catalog.

## When to Use

- A source-to-executor chain is plausible and a safe precursor can distinguish it.
- A warm/hot primitive needs a bounded proof or reduction.

## Evidence Profile

```text
source/control and candidate executor
baseline and inert sibling control
expected safe discriminator and alternatives
process/privilege/sandbox context
preconditions and exact authorization boundary
result, cleanup, residual hypothesis, stop reason
```

## Precursor-First Ladder

1. **Normal baseline:** observe the ordinary request/workflow and choose one
   named primitive question.
2. **Low-impact precursor:** send one scoped representation or process-context
   discriminator that can show whether the suspected boundary is reachable.
   This may be used before a sink is proven; it must stay within the live policy,
   use owned/approved state, and have a clear comparison.
3. **Structural differential:** change one relevant parser, transform, or
   control dimension and compare it with an inert sibling. Before treating a
   no-signal result as negative evidence, state which branch it measured and
   whether the observation channel is reliable for that branch. Do not label an
   otherwise plausible asynchronous/blind consumer cold merely because its
   normal response has no visible difference.
4. **Controlled signal:** after informative precursor evidence, or after the
   active hypothesis record identifies a blind/asynchronous observation gap,
   explain why an available lower-impact measurement is insufficient. Choose
   one permitted deterministic confirmation that distinguishes the active
   branch and correlate it to the request. Visible synchronous effects may use
   a response differential; blind branches may need a bounded delay or an
   out-of-band observer. An observer is eligible only when scoped and authorized
   under the normal platform/program policy; use the task-scoped observer and
   record its ownership, correlation, and cleanup. If a blind branch has no
   authorized observation channel, close as `blocked: observation channel`,
   not `cold`; do not require a callback for a visible branch.
5. **Stop/close:** stop at the first sufficient evidence or record why the
   primitive is cold, blocked, or only an exposure lead.

## Validation Ladder

1. Confirm baseline, control ownership, and the exact question.
2. Use the precursor-first ladder; every step must resolve a named uncertainty.
3. Explain why the observation is not cache, retry, WAF, generic error,
   client rendering, or unrelated background work.
4. Stop at the first sufficient signal and return a confidence label:
   `suspected`, `reachable risky mechanism`, `controlled application effect`,
   or `confirmed bounded impact`.

## Stop

Ask before execution-environment persistence, host/file enumeration, secret
access, interactive shells, privilege change, lateral movement, non-owned
effects, broad worker triggers, or unapproved external callbacks. A normal
application-state write on a verified owned/disposable fixture is not by itself
execution persistence; assess it through the live policy and record cleanup.
When a normal form action has no deletion path, record the bounded expected
residue, why it is necessary to exercise the named primitive, and why fixture
authorization covers that residue; do not treat non-reversibility alone as
execution persistence.

## Completion

The packet is complete only with baseline, negative control, observed result or
closure reason, context/preconditions, cleanup, and an attempt record.
