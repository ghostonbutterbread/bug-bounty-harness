---
name: api-surface-mapping
description: "Use when mapping, comparing, or systematically testing an API surface. Build reconciled operation context and route concrete contracts or discrepancies to their owning skills."
---

# API Surface Mapping

Use this for requests such as “map the API,” “test the API,” “what endpoints
exist,” “compare web and mobile API,” “do these surfaces use the same API,” or
“find hidden API parameters and headers.”

This skill maps API **operations in context**, rather than treating route strings,
a raw captured request, or a status code as a sufficient API model. It is an
adaptive mapping and evidence-routing layer; it does not grant live-testing
permission or replace the owner of a later test decision.

## Load order

1. Load `general-security-testing-policy`, program scope/rules, and the required
   base live chain before target interaction.
2. Load `proxy-routing-policy` for task-MITM setup, proxy history, browser/API
   capture, or Caido-source comparison.
3. Load `bounty-storage` and resolve the active Bounty Core family/lane before
   writing durable artifacts.
4. Add `browser-session-policy` and `chromium-test` for browser-issued,
   stateful, or authenticated flows; add account policy/account selection skills
   when the required owned context is not already known.
5. When scoped JavaScript/source-map request-builder evidence is available or
   needed, use `js`; when wider runtime page/action/auth/state relationships are
   material, use `live-map`.
6. Use `analyze-endpoint` to persist selected per-operation request contracts.

## JavaScript Lens

When JavaScript is relevant, use compact `js` packets and provenance—not raw
bundles—to identify API clients, request builders, serializers, validators,
GraphQL operations, field names, feature flags, and hidden client state. Link a
packet/source reference to the operation record and corroborate source-derived
claims with appropriate runtime evidence. `/js` owns bundle/source-map inventory
and its provenance storage; this skill owns only the API-operation context and
handoff.

## Operation graph

Maintain a reconciled operation record where evidence permits:

```text
operation identity = method + normalized route + semantic capability
  declared by       = OpenAPI / JS / source map / APK / GraphQL document
  observed from     = agent-MITM flow / optional Caido source history
  invoked through   = page, user action, client surface
  context           = auth mechanism, owned role/tenant, prerequisite state
  variants          = headers, query, body, GraphQL variables
  result            = response class + semantic result + state effect
  comparison        = equivalent implementation/surface and unresolved diff
```

For every property, retain whether it is `declared`,
`historically_observed`, `freshly_observed`, `inferred`, or `unknown`. Do not
upgrade a client/source hint to an observed server fact without appropriate
runtime evidence.

A `401`, `403`, `422`, redirect, empty response, or `5xx` is an observation under
one context—not an endpoint conclusion. Record flow provenance, freshness,
authentication context, prerequisite state, and response classification before
interpreting it. Route ambiguous HTTP outcomes through `http-status-live-policy`
before a technique conclusion.

## Evidence provenance

Keep these evidence classes distinct:

1. **Source-declared:** OpenAPI/Swagger, GraphQL documents, JavaScript and source
   maps, mobile clients, request builders, serializers, validators, route
   constants, feature flags, and documentation. They are candidate operation and
   parameter evidence, not reachability/behavior proof.
2. **Runtime-observed:** normal owned-account browser/client actions captured
   through the task-scoped agent MITM. This is the primary source for a current
   contract, flow, auth mechanism, and state effect.
3. **Prior-source:** Ryushe Caido history, when explicitly useful as read-only
   lookup or comparison evidence. Label it historical/source evidence; never use
   it as active transport or merge it into task-MITM replay evidence.
4. **Reconciled:** durable operation/contract records that preserve evidence
   source, freshness, confidence, and unresolved fields.

Do not persist raw cookies, bearer tokens, CSRF values, passwords, API keys,
private request bodies, or reusable non-owned object values. Store sanitized
shape, header/cookie names, auth mechanism, account alias or seed reference, and
evidence pointers.

## Adaptive lenses

The lenses are not a mandatory sequence. Use the source and current runtime
context that best reduces uncertainty, then combine or switch lenses when the
operation graph exposes a concrete comparison or behavior question.

### API estate and contract inventory

Use for cold-start API mapping or “what endpoints exist.”

- Inventory scoped candidate operations from JS/source maps, specs, GraphQL,
  mobile clients, task-MITM observations, and explicit Caido-source comparisons.
- Normalize method, host, path template, content type, operation name, and
  semantic capability where evidence permits.
- Cluster likely equivalents by capability as well as path. Different route names
  can implement one capability; identical paths can have distinct semantics.
- Link candidates to client/page/action, auth state, prerequisites, and evidence.
- Prefer high-information normal flows for capture over hand-generating a large
  request corpus from source declarations.
- Persist selected current operations through `analyze-endpoint`; retain the
  wider inventory and relationships in the API-surface run artifacts.

### Cross-implementation comparison

Use when separate API families or clients may implement one capability: web vs
mobile, REST vs GraphQL, legacy vs current API, BFF vs direct service, or
regional/versioned endpoints.

- Compare normalized route/contract fields, headers by role, auth mechanism,
  prerequisites, schema/content type, and response/state behavior.
- Reconstruct each request in its own fresh, flow-valid owned context. Do not
  transplant stale credentials or browser-bound values and interpret failure as a
  server-side control.
- Compare semantics as well as statuses: authorization outcome, object
  visibility, validation/error category, pagination/filtering, accepted/ignored
  fields, and normal state effect.
- Preserve paired operation IDs, contexts, normalized diff, evidence, candidate
  explanation, and the next evidence need.

### Cross-surface consistency

Use when app areas or clients seem to call the same API or implement the same
business action. Build:

```text
surface / user action → API operation → observed contract variant → result/state effect
```

Compare client-sent versus server-derived object/tenant/role/price/state values;
headers and client markers; hidden/defaulted/silently sent fields; flow sequence;
and authorization, validation, error, and state-transition behavior. Disabled
controls, hidden inputs, hydration values, and feature flags are mapping leads;
verify their server-side relevance through a valid owned context.

### Contract-behavior exploration

Use when a fresh flow-valid operation exists and the question is what the server
accepts, requires, ignores, derives, or trusts.

Use request builders, serializers, validators, sibling requests, UI labels, and
responses to select evidence-backed variants. Preserve a fresh baseline for
stateful flows and change a coherent field group or causal dimension when
comparison is required.

Relevant dimensions include:

- omission versus null, empty, false, zero, empty collection, or type-valid form;
- extra/nested properties, duplicate keys, and query/body precedence;
- enums, state values, feature flags, serializer-only properties, GraphQL
  variables, and hidden client state;
- informational versus routing/version/client-marker/idempotency/anti-forgery/
  authorization-context headers; and
- whether identity, role, tenant, object, price, locale, platform, or workflow
  values are client supplied or server derived.

Treat JavaScript-derived fields as hypotheses, not an unbounded wordlist. Trace
them through client request construction and correlate them with runtime behavior
before routing a concrete lead to `request-exploration`, `headers`,
`idor-live-policy`, `access-control`, or another class-specific owner.

## Protocol and lifecycle mechanics

Do not assume synchronous JSON-over-HTTP. Record observed protocol and lifecycle
shape where relevant: REST, GraphQL, JSON-RPC, gRPC, SOAP, WebSocket, SSE,
upload/download, polling, callback/webhook, or asynchronous job/queue flow.

For concrete operations, consider API host/gateway, version/region/client version,
content negotiation/serialization, pagination/cursors/filtering/sorting, bulk or
partial updates, cache/ETag behavior, idempotency/retry semantics, correlation or
task IDs, eventual consistency, and out-of-band completion paths. Classify the
operation side effect before variation: read, reversible owned mutation,
irreversible/high-impact mutation, financial/fulfillment action, external
notification, or background job.

These are evidence prompts, not a requirement to exercise every feature. When a
concrete question involves concurrency, retries, idempotency, asynchronous
completion, payment, notification, or destructive state, load the policy that
owns that active decision before testing.

## Auth and state context

For selected operations, preserve the auth mechanism and determine when relevant
whether identity, role, tenant, object, and workflow context are server-derived
or client-supplied. Account for cookie/bearer/signed header/device binding/CSRF/
proof-of-possession and one-time, stale, browser-bound, object-bound, or
feature/state-dependent values.

A stale replay proves only that the stale replay failed. For expired/absent auth,
client-fingerprint rejection, nonce/single-use values, or missing normal
prerequisites, rebuild through fresh owned auth and the normal flow/task MITM
where feasible. Only a demonstrated server-side behavior supports a control or
availability conclusion.

## Artifact contract

Write a run under the resolved lane root:

```text
<lane-root>/recon/api_surface_mapping/<run-id>/
  manifest.json
  operations.jsonl
  equivalence_classes.jsonl
  surface_links.jsonl
  contract_diffs.jsonl
  observations.jsonl
  handoffs/
  notes.md
```

These files are attributed run evidence, not canonical appendable URL, parameter,
or hypothesis stores. Retain operation ID; method/normalized host/path/capability;
evidence type/ref; client surface/action; sanitized auth and prerequisite context;
selected `analyze-endpoint` contract path; field/header shape and confidence;
response and state effect; comparison/diff/explanation status; and concrete
handoff evidence.

Use `analyze-endpoint` as the canonical selected-operation contract writer.
Preserve source evidence and task-MITM replay evidence as separate records even
when they describe the same operation. When the run discovers reusable scoped
URLs, parameters, JavaScript URLs, hosts, or content paths, load
`recon-corpus-write-policy` and promote through Recon Bus rather than appending
them to this run. When a plausible distinct security angle appears, load
`hypothesis-expansion-policy` and use `hypothesis-ledger`; create or update the
sanitized `leads` projection when the observed fact leaves one bounded unresolved
security question. Store only the resulting non-secret reference IDs/paths in
the API-surface handoff.

## Bounded sub-agent work

The parent retains scope, account/resource context, active request decisions, and
synthesis. After a compact inventory exists, bounded packets may cover operation
normalization, a specific implementation/surface equivalence class, selected
client request builders, or anomalies. Pass selected operation evidence rather
than raw proxy dumps or broad history. Sub-agent output is a lead/evidence
summary, not an authorization or impact conclusion.

## Handoffs and boundaries

- Per-operation contract and field dictionary → `analyze-endpoint`
- Known-field request variation → `request-exploration`
- Broad parameter aggregation/campaign → `parameter-mining`
- Header/context trust → `headers`
- Object/user/role/tenant/workspace boundary → `idor-live-policy` and/or
  `access-control`
- Client request builder/source evidence → `js`
- Runtime page/action/state graph → `live-map`
- Reusable scoped URL, parameter, JavaScript URL, host, or content path →
  `recon-corpus-write-policy` → Recon Bus
- Plausible distinct security angle → `hypothesis-expansion-policy` →
  `hypothesis-ledger`; add a sanitized `leads` projection when required
- Ambiguous status/challenge → `http-status-live-policy`

Always follow scope, rate, ownership, and live-testing requirements. All active
traffic uses the task-scoped agent MITM; Ryushe Caido remains read-only historical
source evidence except in its separately defined environment. Do not interpret a
source declaration, UI claim, one status, or detached replay as proof of
server-side behavior. Do not perform destructive, financial, fulfillment, public,
or non-owned mutation while mapping a contract; route to the owner policy when a
variation could have such an effect.
