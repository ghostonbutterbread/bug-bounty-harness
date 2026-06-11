# Deep Hunt Playbook

## Purpose

Deep Hunt coordinates focused web hunting on one URL, route cluster, or target
section. It exists to avoid the shallow pattern where agents try a few generic
payloads across many URLs, see no obvious signal, and move on before
understanding the application.

The parent agent is a mapper and coordinator. Child agents are narrow testers.

## Core Model

Depth is section-scoped, not hypothesis-limited.

Good:

- one URL, slow analysis, linked JavaScript review, a few carefully chosen probes
- one route cluster, many separated hypotheses
- one SSO flow, separate redirect/JWT/auth-state/CSRF lanes
- one upload feature, separate file parsing, filename render, CDN, profile,
  admin, email, and export contexts

Bad:

- one child prompt containing XSS, SSRF, IDOR, SQLi, JWT, and payment testing
  across unrelated URLs
- declaring a parameter "not XSS" after only testing raw reflection in one
  response context
- marking dozens of URLs `deep_reviewed` after only status/title checks
- moving to a new app section before recording the exact boundary learned

## Workflow

1. Define the section.

Use a human hint, URL-index route cluster, one full URL, live-map flow, proxy
trace, or `params.txt` cluster. Write the section as a specific app area, not
the whole program.

It is acceptable to leave most URLs unreviewed. Prefer a small batch of URLs
with useful notes over a large batch with shallow coverage.

2. Gather context.

Read existing artifacts before probing:

- URL-index stats, `next`, `history`, route/param-shape related URLs
- live-map routes, flows, auth boundaries, state actions, and handoffs
- hunter-memory claims and failed attempts for the same section
- related JavaScript files, bootstrap data, source maps, route manifests, API
  calls, and frontend sink/source clues
- approved accounts, object/resource IDs, cleanup status, and scope notes

3. Build a section map.

Record:

- entry URLs and related routes
- parameters, bodies, headers, cookies, and route state
- linked JavaScript and observed API calls
- auth states and object/tenant/resource boundaries
- state-changing actions and safe/destructive status
- visible client-side transformations, encodings, and validation boundaries

For a single URL, also record:

- baseline status, length, content type, title, and redirect chain
- whether the route is static, API, SPA, file, redirect, auth, or state-changing
- which linked JavaScript appears specific to the route
- which parameters are likely client-only, server-parsed, routing state, object
  identifiers, callback/URL fields, or search/filter fields

4. Create hypotheses.

Use as many hypotheses as the evidence justifies. Each line should be scoped:

```json
{"id":"H001","section":"search","lane":"xss","skill":"dom-xss","route_cluster":"GET /search","params":["q"],"why":"q reaches SPA route state and search UI updates without full page reload","next_action":"map q source-to-sink in linked JS before payloads","status":"planned"}
```

5. Route child work.

Spawn or brief child lanes only after the packet is narrow. A packet should
usually use one skill:

- reflected value in immediate response -> `/reflected-xss`
- browser source/sink or SPA route state -> `/dom-xss`
- stored write/render contexts -> `/stored-xss`
- URL fetch/import/callback behavior -> `/ssrf`
- object, tenant, role, or workflow boundary -> `/access-control` or `/idor`
- JWT/Bearer/cookie claim behavior -> `/jwt-auth`
- 403 parser/header/path behavior -> `/403`, `/headers`, or `/bypass`
- state-changing weak token/origin behavior -> `/csrf`
- repeated submit/finalize behavior -> `/race`
- SQL-backed parameter behavior -> `/sqli`
- parser/error behavior from a tiny character subset -> `/error-mapper`

Use `/error-mapper` as a helper inside the deep dive when the goal is to learn
how one parameter or route segment fails. Do not use it as a broad fuzzing pass.

6. Record attempts.

Every child or parent attempt should log:

- hypothesis ID
- full URL or route shape
- vector and parameter/header/body field
- technique family
- request variant class, not secrets
- response/browser/proxy signal
- interpretation
- exact boundary learned
- next action or stop reason

7. Decide whether the section is deep-reviewed.

A section is deep-reviewed only when every active hypothesis is one of:

- confirmed and promoted through the owning lane
- blocked by scope/auth/rate/environment with a concrete blocker
- dismissed with a specific observed boundary
- deferred with a concrete next artifact needed

Do not mark a section deep-reviewed just because a payload family failed.

## Hypothesis Separation

Multiple hypotheses for one parameter are allowed. Keep them separate:

```text
q -> reflected-xss: marker appears in HTML body
q -> dom-xss: SPA route reads URLSearchParams
q -> ssrf: backend preview endpoint fetches URL-like values
q -> sqli: API search endpoint has SQL-like error/timing behavior
```

Each hypothesis needs its own evidence, attempts, and stop condition.

## JavaScript Review Expectations

When a section has frontend behavior, review linked JavaScript before or during
payload testing.

Look for:

- route definitions and dynamic params
- URLSearchParams, location/hash/router state, storage, postMessage
- API clients and endpoint construction
- template/render helpers and raw HTML/markdown paths
- sanitizer wrappers, trusted HTML helpers, or framework escape bypasses
- feature flags, hidden UI affordances, role checks, and beta/stable branches
- object IDs, tenant IDs, integration IDs, callback URLs, and redirect handling

The goal is not to audit every JS file. The goal is to find files that explain
how this section behaves.

## Slow URL Deep Dive

When the selected unit is one URL, use this minimum loop:

1. Baseline the URL with the current approved auth state.
2. Identify route family and related route cluster from `/url-ingest`.
3. Review related JavaScript enough to list likely endpoints, params, sinks, and
   client-side transforms.
4. Classify each parameter by likely role: display, search/filter, object ID,
   redirect/URL, file/path, opaque state, analytics, or unknown.
5. Run only a few probes that match the hypothesis: user-agent comparison,
   one or two parameter changes, or `/error-mapper`'s tiny character subset.
6. Record every result through `/url-ingest mark` with `skill`,
   `test-family`, `request-variant`, and `response-summary`.

Do not require every URL to be reviewed. Require every reviewed URL to leave
behind enough context that the next agent knows what was learned.

## Safety

Use the active live-testing and lane policy. Keep probes low-rate and owned.

Stop before:

- non-owned data access
- real user/staff-visible impact
- destructive state changes without approval
- high-volume fuzzing or broad payload spraying
- unbounded character/error probing across many parameters
- brute forcing secrets beyond explicit lab/scope approval
- storing raw credentials, tokens, cookies, private headers, or reset links

## Parent Summary

The final parent summary should answer:

- what section was tested
- what context was gathered
- which hypotheses were pursued
- which child skills were used
- what boundaries were learned
- what findings, if any, were promoted
- what remains for the next section
