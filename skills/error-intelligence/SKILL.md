---
name: error-intelligence
description: Use when errors reveal security-relevant behavior.
---

# Error Intelligence

Use this throughout authorized black-box mapping. Capture errors encountered in
normal use, and explore request, header, identifier, state, or browser behavior
when it helps explain the local application contract. An explicit error-focused
hunt raises priority; it is not required for this default evidence-driven work.

This skill records observed error behavior. It does not replace IDOR/BOLA,
injection, auth, header, or client-side specialist testing.

## Boundaries

Follow the current scope, live-testing, rate, ownership, and attempt-recording
policies before active mutation. Let the observed surface decide how many
comparisons are useful. Keep material differentials interpretable by isolating a
changed dimension before drawing a conclusion. Stop or route on WAF/challenge,
rate limiting, non-owned evidence, destructive ambiguity, financial effect, or
service-degradation risk.

Never put cookies, authorization values, raw private bodies, tokens, secrets, or
unredacted stack traces in Error Store fields.

## Error-Aware Exploration

1. Capture the baseline: HTTP status, response shape and content type, relevant
   request/response headers, timing band, browser console state, and safe
   correlation ID. Completion: later work can identify a real differential.
2. Notice all layers: edge/server/application/dependency/workflow/client;
   errors may be represented in 2xx bodies, redirects, client exceptions, or
   failed browser resources rather than only 4xx/5xx responses.
3. Explore the local contract with comparisons that fit the observed request:
   omission/null/empty, type or cardinality changes, duplicate fields,
   parser/encoding boundaries, content negotiation, headers, state transitions,
   integration/async behavior, and client/server decoding differences. Completion:
   exact deliberate requests belong in Attempts.
4. Treat object-like identifiers as a separate object/access cue. When owned
   two-account prerequisites exist, hand that question to the IDOR/BOLA skill;
   Error Intelligence may separately characterize that request's contract.
5. Record each material new error observation. Promote durable behavior to
   MapStore; retain an exploit idea only as a private Hypothesis Ledger entry.
   An exception alone is never a Finding.

## Store Commands

Use the selected BBH lane's dispatcher:

```bash
bbh agents/error_store.py --family web_bounty --lane web record --program <program> \
  --producer <agent-or-skill> --subject "<normalized-url-or-surface>" \
  --reason "<sanitized observed behavior>" --layer application --channel http \
  --status-or-event 500 --fingerprint "<normalized-redacted-signature>" \
  --trigger-family type --input-location "body.ticket_id"

bbh agents/error_store.py --family web_bounty --lane web query --program <program> \
  --intent events --subject "<normalized-url-or-surface>" \
  --fingerprint "<known-fingerprint>"

bbh agents/error_store.py --family web_bounty --lane web query --program <program> \
  --intent dedupe
```

The Error Store is append-only at the resolved lane. `dedupe` summarizes repeated
fingerprints but does not discard individual observations. It is distinct from:

- Attempts: exact sanitized deliberate probe history.
- MapStore: durable, concise application facts.
- Hypothesis Ledger: private security-chain reasoning.
- Findings: reproducible security impact.

## High-Signal Interpretation

Prioritize repeatable differences; framework/service/version disclosure;
parser/dependency fingerprints; changed behavior by owned auth, role, or workflow
state; different error paths for owned objects; unexpected client/server contract
divergence; exposed correlation IDs; and newly revealed endpoints, consumers, or
trust boundaries. Generic branded errors, known edge/WAF responses, ordinary
validation, and one-off transient failures are normally noise unless they add a
new durable fact.

## Verification

A completed error characterization has a baseline, safe evidence for each
material differential, an Error Store event queryable by route or fingerprint,
and the correct MapStore/Hypothesis/Findings routing decision.
