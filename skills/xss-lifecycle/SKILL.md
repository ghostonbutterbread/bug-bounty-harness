---
name: xss-lifecycle
description: Use when an XSS canary or controlled value may persist, transform, or reach later consumers beyond its initial response or render point.
---

# XSS Lifecycle Expansion

Load after `xss` when a controlled value has signal, when persistence or a
later consumer is plausible, or when a later view exposes the same marker in a
changed representation. This overlay owns the **input-to-consumer graph**; it
does not choose execution payloads or relax live-testing constraints.

## Trigger

Use for a marker or controlled value that is reflected, stored, transformed,
visible in browser state, present in a downloaded artifact, or plausibly carried
through an application workflow. No immediate reflection is required.

Examples include upload filename/metadata, profile fields, drafts, comments,
notifications, exports, emails, data islands, route state, storage, and
framework re-rendering.

## Build The Lineage

Record a compact lineage packet:

```text
producer / write primitive
marker or controlled-value identifier
observed representation and transform
current consumer(s)
possible next processors and owned consumers
account/resource ownership and cleanup state
```

Do not discard a canary after its first response. When direct observation,
browser exploration, proxy evidence, JavaScript mapping, or an owned consumer
shows the marker later or differently, reopen or branch the concrete XSS
hypothesis with that evidence.

## Expansion Loop

1. Identify processing transitions: validation, metadata extraction, storage,
   preview, feed, notification, moderation, email/export, router/state transfer,
   client decoding, and framework re-rendering.
2. Visit or map only relevant owned/approved consumers. Classify every render
   context separately; one stored value may create reflected, stored, and DOM
   lanes at different consumers.
3. Keep the original producer evidence linked to each later consumer. A new
   consumer is a branch, not proof that the original render point was unsafe.
4. Return each branch to `reflected-xss`, `stored-xss`, or `dom-xss` with the
   concrete source, transform, consumer, and browser/raw evidence.

Completion: every discovered consumer is either routed with its own packet,
recorded as unreachable/unsafe to view, or given an exact next observation.

## Optional Sidecars

Split only when the questions are independent and each worker has a concrete
packet:

- application mapper: framework, renderer, source-to-consumer/sink, trust
  helpers, client decoding, and bundle evidence;
- browser observer: rendered DOM, client routing, and raw-versus-browser delta;
- consumer mapper: downstream owned views and delayed workflow/render paths.

The parent XSS agent synthesizes observations and owns hypothesis branching,
payload selection, and closure.

## Boundaries

- Do not create staff-visible, public, non-owned, or hard-to-clean artifacts.
- Do not infer an executable sink from persistence alone.
- Do not close the original vector merely because its first consumer is inert.
- Preserve producer, consumer, transform, ownership, cleanup, and next-question
  evidence in the canonical Attempts stream.
