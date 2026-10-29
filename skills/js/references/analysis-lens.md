# JavaScript behavior and dataflow analysis

**Canonical analysis lens**, owned by `/js`: use for the current relevant JS
file, packet, or flow during any hunt, and from `/js-hunt` for a standalone
campaign. Applying this lens does not by itself start a broad JS hunt, inventory,
or fanout. `/js-hunt` owns campaign breadth and coverage; `/js-pull` owns
acquisition. When current code is missing, acquire only useful scoped material
through `/js-pull` when the user's request and live policies permit.

## Understand the feature

Start with the application capability and available page/flow context: what can
an actor do, what state changes, and what request or browser effect carries it?
Follow the relevant behavior without requiring a full app map. Look for:

- **Features and actions:** routes, navigation, lazy chunks, create/edit/share,
  invite/import/export/delete/connect/payment, and gated or hidden controls.
- **Requests:** API/GraphQL operations, methods, request builders, headers,
  body/query fields, object and tenant IDs, defaults and callers. Separate
  discovered fields from observed server contracts.
- **State and authority:** session, account, role, entitlements and workflow
  state; who sets values, when checks happen, and what the server must enforce.
- **Data and consumers:** URL, form, storage, postMessage, bootstrap/hydration,
  and API-response inputs; parsing, coercion, escaping, later requests, DOM
  writes, navigation, workers/cache, clipboard, or other effects.
- **Secrets and integrations:** actual value, provider, public/private status,
  operation using it and possible capability; generic token/key words alone
  or public client IDs are not proof of secret exposure.
- **Anomalies:** app-specific modules, parsers, debug/admin paths, mismatched
  representations, dormant actions and surprising trust assumptions.

Use deterministic hits and `/jsluice` as starting seeds, not completeness
claims. When reviewing a sink/signature inventory, consult the existing
`skills/js-hunt/references/static-signal-review.md` from the BBH repository root
for per-site interpretation and acquisition gaps. Framework documentation is a
search direction, not proof the application uses a particular consumer.

## Trace and evaluate

Prioritize consequential behavior, plausible controllability, app-specific
logic, observed use, and unexplained trust boundaries; do not require a fixed
score or lead count. Trace a selected transaction:

`actor -> controllable input -> prior state -> transform/check -> decision ->
side effect -> authority boundary`

Follow caller to callee, forward from the value and backward from its final
consumer. Follow lazy modules to their entrypoint and matching build, not a
similarly named archived chunk; source-map names require available source text.
Check encoding, type coercion, serialization, validation, origin, execution
context, and later consumers. Reconstruct request shape where possible.
Identify a plausible benign alternative (constant data, safe text rendering,
server enforcement, inactive route or CSP) and the next discriminator. A
client-side check does not establish absence of server enforcement.

## Evidence and handoff

Cite actual evidence: local path/function or offsets, JS URL, hash, packet or
source-map module, page/flow and nearby scoped request where available.
When the library and indexes exist, query `js_info.sqlite` for aliases and links,
and cite durable packet or JSONL evidence where present. Historical bundles or
GraphQL operation names alone do not establish current reachability. Compare
available page HTML, hidden controls, `data-*` and bootstrap state when consumed
by the code. If provenance, indexes, a request or runtime context is missing,
mark it unknown; do not invent it. Distinguish observed code, plausible execution, observed
browser/proxy request, observed server effect, and validated impact. An offline
hypothesis remains a hypothesis. Explicitly offline work has no network action;
partial local files and packets are usable without acquisition or index writes.

For a concrete observed request use `/analyze-endpoint`; route supported leads
to their specialist: object/role decisions to `/idor` or `/access-control`,
source-to-rendering to `/dom-xss` or `/xss`, object reconstruction to
`rce-deserialization`, workflow invariants to `/business-logic`, and usable
credentials to `/credential-exposure-validation`. Each specialist owns proof;
follow program scope and live-testing policies before live validation. Third-
party URLs in JS are context, not automatic testing permission.
