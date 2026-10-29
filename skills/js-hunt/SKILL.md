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

## Connect the code with the application

For a live JS hunt, the parent can use `live-map` and the task browser/proxy to
understand the relevant feature, actual request and loaded assets, then trace the
corresponding code; a source-derived action or consumer can in turn guide the
next browser observation. Use `technology-research` when a stack detail changes
the question. Correlate the page, flow and asset; code alone does not establish
current reachability or server enforcement. A strong lead need not wait for a
complete map or inventory. Explicitly offline work stays offline; offline workers
never send target requests. Collection-only requests remain collection-only.

## Start and Focus

- Trace a strong lead or available local artifact immediately; an inventory is
  not a prerequisite. Explicitly offline work uses available artifacts with no
  network collection and names missing material as a gap. For broader work,
  reuse a suitable inventory and content-addressed library; if none is suitable,
  use `/js-pull` for scoped collection when the requested work permits it.
  Use whichever inventory metadata, provenance and complete packet paths exist.
  An interrupted inventory may lack final indexes or provenance: review its
  complete packets and record missing metadata as gaps, without resuming
  acquisition in offline work. Work in bounded
  page/flow, bundle-family, route-cluster, or module packets, not a giant prompt.
  Read `source_sites` beside `sink_sites` in bundle and source-map module rows;
  account for truncated/capped sites before declaring a source or sink absent.
  A shared file or nearby offset is a review lead, not a proven data-flow edge.
- For a standalone local artifact without an inventory, inspect the available
  file and relevant local context directly, citing the path and function or
  offsets. Record unavailable provenance and unreviewed material as gaps; do not
  invent a URL, packet, page/flow, request, library entry, or coverage. Skip
  inventory-only queries and observation writes when their inputs do not exist.
- **Only when the library exists**, scope the queue from recorded coverage, not
  from run names. If library records are unavailable, review available files or
  complete packets and report the unknown queue and coverage as gaps instead.
  Content-review
  state lives in sha256-keyed `js_observations` in the library's
  `js_info.sqlite`; `/js-pull` owns writing it and defines the status vocabulary.
  An observation records **depth**, not completion. `/url-ingest` owns per-lane
  URL/parameter *testing* state — a different question, so consult both.
  Selecting run roots by name prefix resembles a currency filter but is not one,
  and can silently drop whole in-scope hosts while the totals still look large;
  group by host and state per-host never-observed, shallow/unknown, and
  deep-claimed counts before
  calling a queue scoped. Use the following two **disjoint** content queues;
  multiple observations may exist for a hash, so a shallow row must not put a
  hash with a deep claim in both queues:

  ```sql
  -- tier 1: no observations for this content
  SELECT DISTINCT a.js_url, a.sha256 FROM js_url_aliases a
  WHERE NOT EXISTS (SELECT 1 FROM js_observations o WHERE o.sha256 = a.sha256);

  -- tier 2: observed, but no deep-review status claim (evidence unchecked)
  -- includes swept, triaged, legacy observed, and unrecognized statuses
  SELECT DISTINCT a.js_url, a.sha256 FROM js_url_aliases a
  WHERE EXISTS (SELECT 1 FROM js_observations o WHERE o.sha256 = a.sha256)
    AND NOT EXISTS (
      SELECT 1 FROM js_observations o WHERE o.sha256 = a.sha256
        AND o.status IN ('deep_reviewed', 'exhausted')
    );
  ```
  Audit unrecognized statuses **independently** of those two queues: a hash may
  have both a deep claim and an unknown-status observation, so the tier 2 query
  alone cannot reveal every legacy/unknown row.

  ```sql
  SELECT DISTINCT a.js_url, a.sha256, o.status FROM js_url_aliases a
  JOIN js_observations o ON o.sha256 = a.sha256
  WHERE o.status IS NULL OR o.status NOT IN
    ('swept', 'triaged', 'deep_reviewed', 'exhausted');
  ```
  Inspect evidence behind `deep_reviewed`/`exhausted` before excluding that
  content from a **specific lens/flow** queue; these content-level queries are
  coarse status summaries, not evidence checks. Exclusion from tier 2 is not
  verification of complete coverage across features or lenses. Reconcile
  unknown statuses; do not count them as completed coverage.
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
those lists. For a sink/signature inventory, read
[`references/static-signal-review.md`](references/static-signal-review.md) to
reconcile per-site hits with stack-specific consumers and acquisition gaps;
this is a review lens, not a second scanner or a completeness claim. Compare
relevant page HTML, hidden controls, `data-*` attributes, and bootstrap state
when the code consumes them. Record visible coverage by feature family and
missing artifact edges rather than saying “all JS checked.”

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

Tie the trace to available evidence: local path/function or offsets, JS URL,
sha256, packet or source-map module, page/flow, and nearby scoped proxy request.
When the library and indexes exist, query `js_info.sqlite` for aliases and links,
and cite the durable JSONL and packet artifacts. For a standalone file, cite its
actual local evidence and mark unavailable provenance and runtime context as
unknown. If a request was observed, load `/analyze-endpoint` to establish its
contract; if not, say so.
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
2. **Selected lead packets:** behavior and why it matters; exact local evidence
   and available JS URL, sha256, packet path, page/flow and request reference;
   source-to-consumer or transaction trace; controllability; observed versus
   inferred edges; missing proof; next discriminator; owning specialist skill.
3. **Coverage and handoffs:** reviewed and unreviewed bundle/flow families,
   truncated maps or missing runtime evidence, candidate wordlists/contracts,
   and separate scoped live-validation hypotheses. When the required inventory
   records exist, mark `/url-ingest` inventory versus `deep_reviewed` only for what
   was actually reviewed, and record per-chunk content coverage through
   `js_analyzer.py observe`; coverage stated only in synthesis prose is not
   queryable and gets re-done. If records are absent, including in an interrupted
   inventory, report exact local coverage and its limits rather than creating or
   claiming indexed coverage. Send useful
   verified observations through `/map-store` and durable notes, not raw bundle
   dumps; dedupe run-local proposals before promoting.

A concrete request goes to `/analyze-endpoint`; object/role decisions to
`/idor` or `/access-control`; source-to-rendering flows to `/dom-xss` or `/xss`;
encoded round-tripped state, type-selected reconstruction, or a behavior-capable
object-loader lead to `rce-deserialization` (its JavaScript Lens owns the
discovery cues; client encoding alone does not prove a backend loader);
workflow invariants to `/business-logic`; usable credentials to
`/credential-exposure-validation`. Load the owning skill only for a supported
lead. Live validation is a **separate** policy-governed step on scoped, owned
resources; offline workers never send target requests. Treat third-party URLs
seen in scoped JS as read-only context, never automatic test targets.

## Scale and Execution

For a small run, the parent can inspect bounded packets itself. For independent
packets, use the native fanout in `skills/js/references/offline-fanout.md`:
role-based surface map and anomaly review, then a focused tracer only when
warranted, with at most three active JS-review subagents. The parent allocates
bounded packets, verifies cited functions, merges duplicates, and covers gaps
without spawning one worker per vulnerability class. Store each worker report
separately under `native_fanout/`. No repository-specific team runner and no
live validation inside this offline pass. `deep` means more evidence-selected
tracing; `offline-fanout` names the optional execution strategy, not another
method.

### Example handoff (illustrative, not a finding)

A workspace invite builder sends `workspaceId`, `email`, and `role`; a UI picker
supplies `viewer`. The JS shows the client's allowed values and request shape,
**not** the server's authorization. The lead asks whether this actor can assign
other roles to an owned workspace member; an observed request and a bounded
owned-account comparison would belong to `/analyze-endpoint` and then
`/access-control`. Until then, status is **requires server confirmation**.
