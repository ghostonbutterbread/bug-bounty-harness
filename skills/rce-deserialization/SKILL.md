---
name: rce-deserialization
description: "Trace deserialization trust boundaries toward RCE."
version: 0.2.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, rce, deserialization, sessions, trust-boundaries]
    related_skills: [rce, rce-exploration, rce-surface-mapping, rce-lifecycle, rce-technology-research, rce-validation]
---

# RCE Through Deserialization

Use from `rce` or `rce-exploration` when externally influenced state may be
rehydrated into runtime objects. The useful question is not whether a blob looks
serialized, but **who can author an accepted representation, which consumer
reconstructs it, and what behavior reconstruction invokes**. This packet owns
that mechanism analysis; `rce-surface-mapping` owns general input-carrier coverage
and `rce-validation` owns live proof selection.

## What It Is and Why It Happens

Serialization turns application state into a representation that can be stored
or transmitted; deserialization reconstructs values from it. The dangerous
boundary is **data choosing runtime behavior**: the loader may resolve classes,
restore attacker-influenced fields, invoke reconstruction hooks, or revive
callables. A *gadget* is existing reachable code whose ordinary behavior becomes
useful in that reconstruction chain; its presence alone does not prove a chain.
Not every format supports those behaviors, and not every object loader permits
arbitrary types. Data-only parsing is not automatically RCE. The runtime-specific
mechanisms and primary sources live in `references/technology-mechanisms.md`.

This often starts as convenience: preserve a rich session or workflow object,
send a job between services, cache an object graph, or restore an export. The
mistake is assuming that state remains trustworthy because the server produced
it, the transport is internal, or the outer wrapper is JSON. Investigate where
an external actor can author accepted bytes, influence a backing store, select
a type, or feed a later consumer with different validation. Keep ordinary
state tampering separate from execution through reconstruction.

## When to Use

- A session, cookie, header, callback state, import, cache, queue, or RPC value
  may contain an object representation, including one nested inside data-only
  JSON or another wrapper.
- Source, errors, documentation, or a bounded format observation suggests an
  object loader, type selection, reconstruction hook, or custom session backend.
- An integrity weakness may make previously trusted serialized state writable.

A framework name, base64 prefix, large cookie, or opaque session ID alone is a
mapping cue, not evidence of an unsafe object loader.

## Reasoning Lens

- **Representation:** follow decoding, decompression, tagged values, nested
  objects, and references to server-side state. Distinguish the outer serializer
  from the inner consumer. An opaque ID needs a backing-store control path, not
  decoding speculation.
- **Accepted control:** separate readable data, attacker-supplied bytes, and
  modifications the consumer actually accepts. A signature is not encryption;
  readability does not imply forgery. Identify verification order and any
  concrete integrity failure: exposed/reused signing material, unsigned fields,
  alternate consumers, or an attacker-writable store. An intact verification
  boundary is a real prerequisite, not a reason to assume a bypass.
- **Reconstruction:** identify the actual library/API, configuration, permitted
  types, and reachable hooks or callables. For pickle, object restoration can
  invoke behavior during loading; returning an unusable object or failing later
  does not prove that reconstruction never ran. Other formats need their own
  runtime/type/gadget preconditions; do not transplant a pickle assumption.
- **Trigger:** find the route or worker that reads the object, not just the
  route that issued or saved it. Callback, resume, retry, preview, cache read,
  or job execution may be the first dangerous consumer. Separate workflow/CSRF
  matching from the integrity boundary; satisfying one does not prove the other.

Use these lenses to choose the next informative observation, not as a fixed
probe sequence. Select topical depth by the current question:

- Identified library, loader, type metadata, or unfamiliar serialization API:
  `references/technology-mechanisms.md` for recognition, prerequisites, and
  benign alternatives; research the observed version/configuration rather than
  reading every technology card as a target checklist.
- Need starting places or a different explanation of a blocked path:
  `references/investigation-ideas.md` for conditional mechanisms, controls, and
  falsifiers. These are recall aids, not an exhaustive tricks list.
- Nested session objects or a signing/loader chain:
  `references/session-object-case.md` for the report-derived example and the
  distinction between default Flask state and embedded pickle.

## JavaScript Lens

Use `js` → `js-pull` for the existing scoped corpus and `js-hunt` for function-
level tracing. Look in request builders for import/restore/resume operations,
serialized job arguments, round-tripped bootstrap state, and fields carrying
encoded blobs or type metadata. Follow the actual named field through encoders,
request submission, response, and later action; `state`, `data`, `payload`,
`$type`, or `@class` by themselves are weak search seeds, not server contracts.
Relevant serializer imports/custom revivers and available source-map code can
clarify behavior, but establish whether they execute in a browser or backend.

Keep the JS URL/hash, function or module, page/flow, field, transforms,
destination, and observed request reference together. A client encoder, base64
operation, `JSON.parse`, or nearby library name does not identify a backend
object loader. Inspect code beyond signatures, including lazy chunks and
non-JS carriers such as HttpOnly cookies visible in authorized browser traffic.
An opaque server-state ID needs a writer/control path to its backing object.
These are review seeds in the existing inventory, not a new analyzer mode or
a claim that the XSS source/sink census detects deserialization. A heuristic
miss does not close this lane; preserve missing backend/worker evidence.

## Investigation and Handoff

Use existing source/runtime evidence to sketch:

`carrier → acceptance/integrity gate → transforms → object loader → trigger → effect`

Annotate each edge as observed, source-supported, inferred, or unknown. Preserve
baseline and inert control references. Decode as data and inspect formats without
executing reconstruction: never use `pickle.load`, `pickle.loads`, or
`python -m pickle` to inspect untrusted evidence on the agent host. Python's
`pickletools` can inspect opcodes without executing them; bound input size,
decompression, resource use, and secret-bearing output too.
The same inspection boundary applies to other behavior-capable loaders: do not
run untrusted evidence through PHP unserialize, Java object streams, Ruby
Marshal, unsafe YAML constructors, or function-reviving JavaScript on the agent
host. Use inert structural inspection; executable reproduction belongs in an
authorized disposable lab under the existing testing policy.

Route unresolved stack/configuration questions to `rce-technology-research`,
later consumption to `rce-lifecycle`, and a named plausible chain to
`rce-validation` under the existing authorization and live-testing policies.
Do not copy a report's delays, callbacks, key guessing, or cross-host tests as
a default. Follow `cookie-session-analysis`'s synthetic-only boundary if using
its packaged CLI; this packet does not provide a live-cookie adapter.

## Pitfalls and Verification

- Default Flask session handling is not evidence of pickle use; an application
  may embed an object inside a data-only container or use a custom backend.
- A decoded class name supports a format lead, not server-side reachability.
  A valid signature or accepted field demonstrates control, not RCE by itself.
- A rejection closes only the tested representation, gate, consumer, and trigger;
  a missing observation channel is not a global negative.

Return the carrier and ownership, transform chain, acceptance boundary, loader
and runtime prerequisites, actual trigger/context, baseline/control references,
observed effect or exact missing edge, and the existing evidence/cleanup record.
Do not create a second ledger or treat a public case as target proof.
