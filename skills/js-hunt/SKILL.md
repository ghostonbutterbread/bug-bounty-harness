---
name: js-hunt
description: Use when hunting JavaScript for behaviors, hidden surfaces, and testable security leads.
---

# JavaScript Hunt

An unqualified “hunt the JavaScript” runs this **whole adaptive methodology**.
The agent maps the app's client-visible behaviors, chooses consequential or
unusual flows, traces them deeply, and hands off specific questions. It does
not stop at endpoint extraction, run a fixed vulnerability-class matrix, or
claim exhaustive coverage from a scanner. Collection mechanics belong to
`/js-pull`; class-specific live validation belongs to the owning skills.

## Start and Focus

- If a suitable inventory exists, reuse its run root and content-addressed
  library. Otherwise load `/js-pull` once for scoped collection. Start from
  `manifest.json`, `metadata.jsonl`, `packets.jsonl`, page/JS provenance,
  source-map module index, and completed packet paths. Work in bounded
  page/flow, bundle-family, route-cluster, or module packets, not a giant prompt.
- **Scope the queue from recorded coverage, not from run names.** Content-review
  state lives in sha256-keyed `js_observations` in the library's
  `js_info.sqlite`; `/js-pull` owns writing it. It answers "has this *content*
  been read", while `/url-ingest` owns per-lane URL/parameter *testing* state —
  different questions, so consult both. Selecting run roots by name prefix
  resembles a currency filter but is not one, and can silently drop whole
  in-scope hosts while the totals still look large; group by host and state
  per-host reviewed/unreviewed counts before calling a queue scoped.

  ```sql
  -- unreviewed content (qualify a.js_url, else SQLite reports an ambiguous column)
  SELECT a.js_url, a.sha256 FROM js_url_aliases a
  LEFT JOIN js_observations o ON o.sha256 = a.sha256
  WHERE o.sha256 IS NULL;
  ```
- Default **broad hunt**: survey all meaningful application-owned feature
  families represented in the inventory, including a classless anomaly pass.
  Rank then deep-review selected flows. When inventory is too large, declare
  which families were sampled and which remain unreviewed; no fixed number of
  leads or agents substitutes for a coverage decision.
- Narrow hunt: `--focus endpoints`, `--focus params`, `--focus secrets`,
  `--focus application-logic`, or `--focus dataflows`. These are named views of
  the same pipeline, not separate parsers or mandatory subagent roles. Spend
  depth on the requested view, and report strong adjacent evidence without
  pretending to have broadly reviewed other areas. Natural-language synonyms
  route here too.

## 1. Broad Behavior Map

Before sorting findings by vulnerability class, group the reviewed code by
**application capability** and the page/flow that loads it. Ask what the user
can do, what changes, and what request or browser effect carries the action:

- **Features and actions:** routes, navigation, lazy chunks, create/edit/share/
  invite/import/export/delete/connect/payment flows, gated or hidden controls.
  A route string or feature flag is not proof of current reachability.
- **Request vocabulary:** API/GraphQL operations, methods, request builders,
  body/query/header fields, object and tenant IDs, parameter defaults and
  allowed values, callers that actually submit them. Separate discovered
  fields from observed server contracts.
- **State and authority:** session/account/role/entitlement and workflow state;
  who sets each value, when checks happen, what the client hides or blocks,
  and what must still be independently enforced at a server boundary.
- **Data movement and consumers:** URL, form, storage, postMessage, bootstrap/
  hydration and API-response inputs; parsing/coercion/escaping; later requests,
  DOM writes, navigation, workers/cache, clipboard, or other effects.
- **Secrets, config, and integrations:** concrete value, provider, intended
  public/private status, the operation consuming it, and potential capability.
  Generic `KEY`/`token` words or public client IDs alone are low-signal.
- **Anomalies:** rare app-specific modules, custom parsers, debug/admin paths,
  mismatched representations, dormant actions, surprising trust assumptions,
  and state machines that do not fit a named class.

Use deterministic hits and `/jsluice` as **starting seeds**; inspect code beyond
those lists. Compare relevant page HTML, hidden controls, `data-*` attributes,
and bootstrap state when the code consumes them. Record visible coverage by
feature family and missing artifact edges rather than saying “all JS checked.”

## 2. Prioritize and Deep Trace

Prioritize **consequential behavior**, plausible user control, app-specific
logic, observed use in page/proxy flow, and unexplained trust boundaries. A
high-consequence but unobserved action may be worth tracing; a generic vendor
keyword usually is not. Do not turn this into a mandatory score or hard lead
cap. Revisit the broad map before ending so one strong lead does not silently
replace the rest of the user's broad hunt.

For each selected candidate, write a transaction:

`actor -> controllable input -> prior state -> transform/check -> decision ->
side effect -> authority boundary`

Trace caller to callee and **forward from the value and backward from the final
consumer**. Follow a lazy module to its entrypoint and matching build, not a
similarly named archived chunk; follow a source-map name only when its text is
available. Check encoding, type coercion, serialization, validation, origin,
execution context, and later consumers. Reconstruct an exact request shape
where possible. State the strongest benign alternative (constant data, safe
text rendering, server-side enforcement, inactive route, CSP, etc.) and one
next discriminator. A client-side check never proves that the server lacks one.

## 3. Correlate, Classify, and Hand Off

Tie the trace to the JS URL, sha256, packet path/function or source-map module,
page/flow, and nearby scoped proxy request. Query `js_info.sqlite` for aliases
and links, but cite the durable JSONL and packet artifacts. If a request was
observed, load `/analyze-endpoint` to establish its contract; if not, say so.
Do not infer current reachability from a historical bundle or a GraphQL
operation name alone.

For each lead distinguish **observed in artifact**, **plausible execution
path**, **observed browser/proxy request**, **observed server effect**, and
**validated impact**. Record controllability, missing proof, best alternative,
next discriminator, and confidence at the actual evidence level. An offline
hypothesis remains a hypothesis even when the code looks dangerous.

Output three bounded sections:

1. **Surface map:** feature families, actions, request/field vocabulary, and
   noteworthy decisions or data flows with evidence pointers.
2. **Selected lead packets:** behavior and why it matters; exact JS URL,
   sha256, packet path, page/flow and optional request reference; source-to-
   consumer or transaction trace; controllability; observed versus inferred
   edges; missing proof; next discriminator; owning specialist skill.
3. **Coverage and handoffs:** reviewed and unreviewed bundle/flow families,
   truncated maps or missing runtime evidence, candidate wordlists/contracts,
   and separate scoped live-validation hypotheses. Mark `/url-ingest` inventory
   versus `deep_reviewed` only for what was actually reviewed, and record
   per-chunk content coverage through `js_analyzer.py observe`; coverage stated
   only in synthesis prose is not queryable and gets re-done. Send useful
   verified observations through `/map-store` and durable notes, not raw bundle
   dumps; dedupe run-local proposals before promoting.

A concrete request goes to `/analyze-endpoint`; object/role decisions to
`/idor` or `/access-control`; source-to-rendering flows to `/dom-xss` or `/xss`;
workflow invariants to `/business-logic`; usable credentials to
`/credential-exposure-validation`. Load the owning skill only for a supported
lead. Live validation is a **separate** policy-governed step on scoped, owned
resources; offline workers never send target requests. Treat third-party URLs
seen in scoped JS as read-only context, never automatic test targets.

## Scale and Execution

For a small run, the parent can inspect bounded packets itself. For independent
packets, use the native fanout in `skills/js/references/offline-fanout.md`:
first-wave general-map and anomaly workers, parent verification, then only
justified broad follow-ups. Store each worker report separately under
`native_fanout/`; the parent checks cited functions and merges duplicates. No
fixed all-class team, no repository-specific team runner, and no live validation
inside this offline pass. `deep` means more evidence-selected tracing;
`offline-fanout` names the optional execution strategy, not another method.

### Example handoff (illustrative, not a finding)

A workspace invite builder sends `workspaceId`, `email`, and `role`; a UI picker
supplies `viewer`. The JS shows the client's allowed values and request shape,
**not** the server's authorization. The lead asks whether this actor can assign
other roles to an owned workspace member; an observed request and a bounded
owned-account comparison would belong to `/analyze-endpoint` and then
`/access-control`. Until then, status is **requires server confirmation**.
