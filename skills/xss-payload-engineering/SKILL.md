---
name: xss-payload-engineering
description: Use when a warm or hot XSS vector needs payload families composed from the observed context, primitives, transforms, browser, framework, and defenses.
---

# XSS Payload Engineering

Load after `xss` and the selected reflected/stored/DOM lane when the next task
is payload selection, mutation, or reduction. This overlay turns observations
into candidate families; it does not treat a payload corpus as an exhaustive
ceiling or make a vulnerability claim without browser proof.

## Capability Profile

Build and update this compact profile while testing:

```text
source and render/sink context
surviving, blocked, escaped, and normalized primitives
encoding/decode and browser-reparse stages
framework, renderer, sanitizer/trust boundary, and CSP
edge/WAF versus origin behavior
raw HTTP versus browser result
current consumer and any later-consumer branch
```

Use the profile to answer: **what language can this input still speak, and
which executable consumer could interpret it?**

## Candidate Queues

Keep both queues available for a plausible warm/hot vector.

### Context-Directed Queue

Select families that answer the observed parser question: text/attribute/tag
breakout, URL scheme, script/JSON/template literal, markdown/XML/iframe,
DOM-source, storage/message, sanitizer, or framework trust-wrapper behavior.

### Exploratory Queue

Use when the vector remains plausible or a research/JS/browser clue warrants
broader creativity: unusual parser/browser grammar, polyglots, mutation XSS,
DOM clobbering or structural influence, alternate namespace/event forms,
framework-specific primitives, and research-derived candidates.

An exploratory candidate may be surprising or model-generated. Record its
source/parent, mutation operations or generator seed when applicable, placement,
and browser/origin result. If it signals, reduce it through follow-up comparisons
until the responsible parser, transform, or consumer boundary is understood.

## Defense And Research Routing

- Load `waf-live-policy` when filtering, normalization, challenge, or an edge
  differential becomes the interesting boundary. Classify the boundary before
  choosing a materially distinct representation.
- Load `xss-technology-research` when an observed stack or defense fingerprint
  could change the candidate queue.
- Return to `xss-lifecycle` when a controlled value gains a later consumer or a
  changed representation.

## Completion

A payload family is covered only when its relevant context/transform boundary is
understood, it branches to another consumer, or policy stops the next probe.
Do not summarize a lane as "blocked" without its family coverage, observed
transform, browser result, residual hypothesis, and exact stop reason.
