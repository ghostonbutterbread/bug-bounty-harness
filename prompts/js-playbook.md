# JavaScript Analysis Playbook

## Purpose

Analyze JavaScript deeply without wasting agent context on collection, dedupe,
or raw bundle sprawl. Scripts do high-volume deterministic work; agents do
interpretation and security reasoning.

## Modes

`analyze`:

- inventory JavaScript from a page, aggregate file, proxy history, or recon run
- deep-review selected chunks
- produce endpoints, params, sinks, sources, source maps, auth/storage notes,
  framework clues, flow hints, interesting object/request keys, confidence, and
  follow-up questions

`generate`:

- use reviewed JavaScript evidence to create candidate route/param/action packs
- hand packs to `/create-wordlists`
- route campaign execution to `/use-wordlists` or `/fuzz`

`deep`:

- prioritize depth over breadth
- chunk by page, bundle family, source map/module boundary, route cluster, or
  stable byte windows
- spawn bounded specialist agents only when chunks are independent and the user
  wants the budget spent on this task

## Analysis Lenses

`/js` is the JavaScript evidence router. It should not force every worker to
look at every possible issue class. Pick the lens before deep review, then hand
concrete leads to the owning skill.

Available lenses:

- `general-map`: map page context, provenance, routes, API clients, params,
  request builders, source maps, feature areas, and durable notes. Use this as
  the first pass when the user asks for a general JavaScript review.
- `secrets`: inspect for usable API keys, provider tokens, GitHub/package/cloud
  identifiers, signed URLs, public/private config leakage, and scope-expanding
  secrets. Downgrade generic words like token/password/secret unless there is a
  concrete value and impact path.
- `dom-xss`: trace URL/search/hash, storage, postMessage, form, hidden DOM, and
  bootstrap-state sources into DOM writes, script creation, navigation, template
  rendering, or eval-like sinks. Hand concrete traces to `/dom-xss` or `/xss`.
- `access-control`: trace roles, permissions, admin flags, team/org/workspace,
  brand, entitlement, group, SCIM/class, invite, and ownership logic. Hand
  request-backed leads to `/access-control`.
- `idor`: map object identifiers and object-boundary assumptions for designs,
  folders, files, media, templates, invoices, subscriptions, comments, users,
  teams, brands, and projects. Hand request-backed leads to `/idor`.
- `business-logic`: inspect workflow state machines, install/connect flows,
  feature gates, paid/free gates, share/publish/import/export controls,
  client-side validation, and unsafe assumptions about server enforcement.
- `ssrf-import`: inspect URL importers, preview/fetch resolvers, webhooks,
  embed/codelet loaders, favicon/image fetchers, remote media, redirect
  handling, and server-side URL resolution hints. Hand request-backed leads to
  `/ssrf`.
- `auth-ato`: inspect login, signup, reset, recovery, invite acceptance,
  OAuth/SSO/SAML, captcha/risk scoring, session binding, identity linking, and
  email/account-change flows. Hand leads to `/ato` or `/password-reset`.
- `payment`: inspect checkout, coupons, credits, invoices, subscriptions,
  refunds, plans, pricing, paid entitlements, and billing object IDs. Hand
  zero-dollar-first leads to `/payment-testing`.
- `request-shape`: extract request builders, API clients, GraphQL operations,
  headers, content types, body schemas, and proxy-observed request contracts.
  Hand concrete requests to `/analyze-endpoint` before vuln-lane testing.

General review order:

1. Run `general-map` to classify packet families and choose lenses.
2. Split specialist workers by lens and packet family.
3. Each worker writes concise findings with source JS URL, SHA, packet path,
   trace, controllability, provenance/proxy links, confidence, and next skill.
4. The main agent merges results into dated notes/handoffs and routes only
   concrete, scoped follow-ups to the owning skills.

Avoid assigning one agent every lens for hundreds of packets. That creates
shallow output and repeated context burn. Use metadata to rank, then route.

## Script-First Layer

Use deterministic scripts before asking agents to reason over code.

Primary helper:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"

python3 agents/js_analyzer.py inventory canva \
  --input "$HOME/Shared/web_bounty/canva/web/recon/aggregated/jsfiles.txt" \
  --target-host canva.com \
  --run-id js-canva-$(date -u +%Y%m%dT%H%M%SZ) \
  --limit 100
```

For a single page:

```bash
python3 agents/js_analyzer.py inventory canva \
  --page "https://www.canva.com/login" \
  --page-context "login/auth flow" \
  --target-host canva.com
```

The helper writes:

```text
~/Shared/web_bounty/<program>/web/recon/js/<run-id>/
├── manifest.json
├── metadata.jsonl
├── page_context.jsonl
├── js_provenance.jsonl
├── packets.jsonl
└── packets/<sha-prefix>-NNN.md

~/Shared/web_bounty/<program>/web/recon/js/_library/
├── ledger.json
├── provenance.jsonl
├── js_provenance.sqlite
├── downloads/<sha256>.js
└── chunks/<sha256>/<chunk-set-key>/
    ├── manifest.json
    └── NNN.js
```

## Provenance And Proxy Correlation

JavaScript is most useful when agents know where it came from and what browser
or proxy traffic happened around that page. Do not treat a JS URL as a detached
file if page/proxy provenance is available.

Preserve a JS provenance index whenever collection comes from browser crawl,
Caido/Burp/MITM proxy history, Playwright/CDP network events, or recon-ry/Katana
outputs that include referrer/initiator data. Store it beside the JS run and in
the shared JS library where possible. The append-only JSONL files are the source
of truth. The SQLite DB is generated from the JSONL and exists so agents can
query relationships quickly without loading every packet or metadata row.

```text
web/recon/js/<run-id>/js_provenance.jsonl
web/recon/js/_library/provenance.jsonl
web/recon/js/_library/js_provenance.sqlite
```

Recommended row fields:

- `js_url`, `sha256`, `run_id`, `first_seen`, `last_seen`
- `page_url` or `document_url` that loaded the script
- `page_context`, such as login/auth, editor, billing, settings, admin, share,
  app/integration, upload/import, or unknown
- `source`, such as page crawl, recon aggregate, Ryushe proxy, agent proxy,
  recon-ry/Katana, Wayback, or manual input
- `proxy_request_id` or raw-request reference when available, never live cookies
  or secret headers
- `initiator`, `referrer`, `frame_url`, `method`, `status`, `content_type`, and
  timestamp when the source can provide them
- `related_requests`: nearby scoped API requests observed in the same page flow,
  with sanitized references to proxy rows or `/analyze-endpoint` artifacts

Use the DB for lookup questions:

- which pages or flows loaded this JavaScript URL?
- which JS URLs were seen by Ryushe proxy, agent proxy, Katana, Playwright, or
  manual input?
- which URLs map to this content hash?
- which scripts belong to login, billing, editor, admin, upload/import, or
  integration flows?
- which proxy request IDs or endpoint contracts are near this script?

Keep citations and durable handoffs tied to the JSONL row, manifest, packet
path, source JS URL, SHA256, and any sanitized proxy/analyze-endpoint artifact.
If the SQLite schema changes, rebuild it from `_library/provenance.jsonl`; do
not treat DB-only rows as durable evidence.

When a deep-review worker selects a packet, it should first ask:

1. Which page or app flow loaded this JS?
2. Which scoped proxy requests happened before and after this script loaded?
3. Do the JS-discovered fields appear in real request bodies, query strings,
   headers, GraphQL operations, or route params?
4. Is there a saved `/analyze-endpoint` contract for those requests?

Ryushe proxy and agent proxy are complementary sources:

- Ryushe proxy is read-only historical evidence from manual testing. Use it to
  learn where features were used, what request shapes appeared, and which
  account/page context produced them.
- Agent/local proxy can be used for bounded owned-account reproduction after the
  JS/proxy correlation gives a concrete scoped request to observe. Replays must
  keep fresh auth, owned resources, normal rate, and scope controls.

Do not jump from JS evidence directly to mutation. The routing should be:

```text
JS packet lead -> provenance page/flow -> proxy request candidates ->
/analyze-endpoint contract -> vuln-lane plan -> bounded owned-account test
```

Script responsibilities:

- collect JS URLs from pages, aggregated recon, proxy/recon artifacts, Wayback,
  and source maps when available
- download JS bodies with rate control
- check `ledger.json` before fetching a URL that has already been mapped to a
  content hash
- hash and dedupe by content so the same bundle from proxy, recon, Wayback, or
  page collection is stored once
- keep raw bundles on disk in the shared `_library`
- record URL aliases under the same file hash when platforms serve the same JS
  from multiple URLs
- preserve provenance for each JS URL when available: page/document URL,
  initiator/referrer, proxy source, request id, and nearby scoped API requests
- accept optional provenance input JSONL with `--provenance-input` so proxy,
  browser, or recon-ry collectors can pass page/flow/request relationships into
  the JS inventory run
- write per-run `js_provenance.jsonl`, append to `_library/provenance.jsonl`,
  and refresh `_library/js_provenance.sqlite`
- extract cheap signals: URLs, API paths, params, imports, source maps,
  source/sink keywords, framework/router clues, GraphQL operations, route hints,
  interesting object/request keys, and flow categories
- split extracted endpoints into in-scope endpoints and external
  integration/reference endpoints when `--target-host` is provided
- write external integration/reference URLs into the program integration index
  under `~/Shared/web_bounty/<program>/web/intel/integrations/`
- treat generic secret words as secondary context; prioritize usable API keys,
  GitHub/package/cloud/service identifiers, and keys that expand reachable scope
  over noisy "token/password/secret" matches
- store chunk sets by file hash plus chunk settings, then write bounded packet
  files for agents

Use `--refresh` only when intentionally checking whether a URL's content has
changed:

```bash
python3 agents/js_analyzer.py inventory canva \
  --input "$HOME/Shared/web_bounty/canva/web/recon/aggregated/jsfiles.txt" \
  --target-host canva.com \
  --provenance-source recon-aggregate \
  --refresh
```

Without `--refresh`, the helper reuses the URL-to-hash ledger and avoids another
download when the artifact is already present.

## Agent Deep Review

Agents consume packet files, not raw program-wide bundle lists.

Review goals per packet:

- What application area does this JS support?
- Which page, route, proxy flow, or manual testing path loaded this JS?
- Do Ryushe proxy or agent-proxy records show this script's fields in real
  scoped requests, and can those requests be linked to sanitized endpoint
  contracts?
- What endpoints, params, request fields, GraphQL operations, or action names
  does it reveal?
- Which functions actually move data? For each suspicious source, sink, request
  builder, navigation helper, DOM write, permission check, or object lookup,
  trace the value through assignments, wrappers, callers, callees, guards, and
  transformations before deciding whether it matters.
- Can the value be controlled? Identify whether it comes from URL/search/hash,
  hidden DOM fields, `data-*` attributes, bootstrap JSON, storage, postMessage,
  forms, server-rendered state, proxy-observed responses, or only hardcoded
  constants.
- How are auth, sessions, CSRF, local/session storage, cookies, and feature
  flags handled?
- What user/team/org/workspace/project/design/invoice/subscription identifiers
  appear, and do they suggest `/idor` or `/access-control` follow-up?
- Are there source-to-sink paths: URL/hash/search/storage/message/form input to
  DOM write, navigation, eval-like calls, request bodies, template rendering, or
  upload/import sinks?
- Are there object IDs, tenant IDs, roles, entitlement names, team/project IDs,
  or workflow states worth routing to `/idor` or `/access-control`?
- Are there URL fetchers, importers, previews, webhooks, image loaders, or
  server-side fetch hints worth routing to `/ssrf`?
- Are there search/filter/sort/report/export inputs worth routing to `/sqli`,
  `/xss`, `/ssti`, or `/request-exploration`?
- Are referenced third-party integrations evidence of a Canva-owned connect,
  callback, import, or app-install flow? Treat third-party URLs as context, not
  test targets, unless the program scope explicitly includes them.
- If a suspicious function is only partly visible in one chunk, use
  `packets.jsonl` and the chunk-set manifest to inspect adjacent chunks from the
  same file hash before finalizing the review.
- If the JavaScript reads hidden or non-rendered page state, compare it with the
  actual page HTML/source during follow-up. Hidden inputs, hydration scripts,
  JSON blobs, `data-*` attributes, disabled controls, feature flags, and
  template fragments can expose IDs or flow switches that are absent from the
  rendered UI.

## Signal Priority

High-value JS analysis is flow-first, not secret-first.

Prioritize:

- function-level source-to-sink traces with controllability, not just keywords:
  `source -> transform/check -> caller/callee -> sink/request/DOM effect`
- hidden API routes, GraphQL operations, request builders, route templates, and
  client-side API wrappers
- parameter and field names, especially object IDs, tenant/team/workspace IDs,
  redirect URLs, callback URLs, file paths, import/export/upload/download fields,
  payment fields, and authorization fields
- sources and sinks that imply DOM XSS, open redirect, client-side SSRF-like
  fetch flows, request manipulation, storage/session handling, or script/HTML
  injection
- feature flags, experiments, beta gates, admin/role checks, entitlement names,
  and client-side assumptions that can guide targeted testing
- hidden or non-rendered page state consumed by JavaScript: hidden inputs,
  `data-*` attributes, bootstrap JSON, hydration globals, inline config scripts,
  disabled controls, and template-only form fields
- third-party service identifiers and API keys only when they plausibly expand
  reachable scope or unlock a real integration path

Scope rule:

- JavaScript file collection should use `--target-host` so fetched bundles come
  from the program-owned host or child domains.
- Extracted URLs inside scoped JavaScript can include third-party integrations.
  Keep those as integration evidence only. Do not test the third party unless
  the bounty scope explicitly includes it.
- Prefer finding the Canva-owned route, callback, request builder, app-install
  endpoint, or proxy-observed request that uses the integration fields.

External URL triage:

- Safe to inspect as evidence: the URL string itself, its query/field names, the
  owning integration name, whether it is public documentation/marketplace/help
  content, and whether the scoped app sends users or server-side requests to it.
- Safe to open with normal browser hygiene: public documentation, marketplace
  listings, static policy/help pages, and public integration landing pages,
  when the purpose is only to understand the integration flow.
- When opening these pages, keep the action read-only: record the final URL,
  title, description, visible purpose, query parameters, and how it relates
  back to a scoped route. Do not log in, install apps, grant OAuth consent,
  submit forms, replay requests, mutate parameters, or probe the third-party
  service.
- Do not fuzz, mutate, replay, brute-force, authenticate against, or probe the
  third-party host unless it is explicitly in the bounty scope or Ryushe
  explicitly approves a separate target.
- If a referenced external URL contains what looks like a token, API key,
  signed URL, private file, or exposed data, preserve only sanitized evidence in
  notes and pivot back to the scoped program question: did Canva leak it, embed
  it, proxy it, or expose a Canva-owned endpoint that uses it?
- If the external URL implies a useful integration, route the next step toward
  the scoped endpoint that creates, connects, imports, redirects, or callbacks
  through that integration.
- Store external URLs as world/intel facts, not as targetable scope:
  - per-run copy: `web/recon/js/<run-id>/external_integrations.jsonl`
  - cross-run index: `web/intel/integrations/external_urls.jsonl`
  - host summary: `web/intel/integrations/external_hosts.json`
- Each row should preserve where it was found: external URL, host,
  classification, action policy, allowed read-only context actions, source JS
  URL, source SHA256, run id, page context, target host, and evidence path.
- Future agents can load the host summary first, then open only the relevant
  run/packet evidence when asking "where did we see this integration?"

Deprioritize:

- generic "token", "secret", "password", or "authorization" strings without a
  concrete value, source, route, or impact path
- minified vendor-library noise unless it exposes app-specific endpoints,
  wrappers, sinks, or configuration
- raw secret-scanner style output that duplicates what `secrets.txt` or a basic
  scanner would already report

## Deep Review Output Template

Use this shape for packet reviews so follow-up agents can act without rereading
the whole bundle:

```text
Lead: <short title>
Lane: </ato | /access-control | /idor | /dom-xss | /ssrf | /request-exploration | /analyze-endpoint | /create-wordlists>
Evidence: <exact strings, functions, fields, routes, or packet lines>
Trace: <source -> transforms/checks -> caller/callee -> sink/request/DOM effect>
Controllability: <controlled | partly controlled | server-set | hardcoded | unknown, plus why>
Hidden state check: <DOM/HTML/bootstrap fields to inspect, if any>
Why it matters: <flow, trust boundary, object boundary, or hidden surface>
Confidence: <low | medium | high>
Gating condition: <what must be true before live testing>
Adjacent chunks: <packet numbers, chunk files, lazy imports, or source-map modules>
Next test: <one bounded follow-up using owned accounts/resources>
```

Example:

```text
Lead: App integration route/client ID authorization
Lane: /access-control
Evidence: Sm/Via/$ia, appId, clientId, source, Pq, context, /your-apps/.../shopify-connect
Why it matters: client-visible app IDs and connect routes may route into install/open flows.
Confidence: medium
Gating condition: proxy traffic shows server endpoints accepting appId/clientId/source fields.
Adjacent chunks: inspect /apps/ routing chunk and definitions of Rm/Wia/Xia.
Next test: compare owned-account app-connect requests across allowed vs uninstalled apps.
```

## Page Context

Always preserve why the JavaScript was collected.

Examples:

- login/auth page: prioritize redirects, token handling, OAuth/SAML, CSRF,
  password reset, storage, and session transitions
- billing/checkout page: prioritize payment state, coupons, entitlements,
  invoice/refund/subscription endpoints
- editor/collaboration page: prioritize design IDs, invite/share links,
  permissions, comments, uploads, import/export, and real-time channels
- admin/settings page: prioritize role/tenant/object-boundary APIs

The model behavior should be consistent, but the context changes the threat
model and priority ranking.

## Coverage And State

Use `/url-ingest` for URL/JS coverage state:

```bash
python3 agents/url_ingest.py mark canva \
  --url "https://static.canva.com/app.js" \
  --lane recon \
  --status surface_reviewed \
  --skill js \
  --test-family js-inventory \
  --technique script-first-inventory \
  --evidence "~/Shared/web_bounty/canva/web/recon/js/<run-id>/manifest.json"
```

After agent deep review, mark the JS URL or route as `deep_reviewed` for
`--skill js --test-family js-deep-review`.

Use `/bounty-notes` for durable summaries and handoffs when review produces
learning that future agents need.

For meaningful JS runs, keep the large artifacts under `web/recon/js/` and write
small linked notes under `notes/`:

```bash
python3 agents/bounty_notes.py note canva \
  --family web_bounty \
  --lane web \
  --bucket handoffs \
  --title "<js-run-id>" \
  --slug "<js-run-id>" \
  --agent codex \
  --run-id "<js-run-id>" \
  --tag js \
  --url "https://static.canva.com/app.js" \
  --refs "~/Shared/web_bounty/canva/web/recon/js/<js-run-id>/manifest.json" \
  --refs "~/Shared/web_bounty/canva/web/recon/js/<js-run-id>/packets/<packet>.md" \
  --body-file /tmp/js-handoff.md
```

Use `notes/hypotheses/` for individual testable leads, such as app-install
authorization, URL import server fetch, content-share IDOR, or folder lookup
access-control. Link back to packet paths with `--refs`; do not duplicate whole
packets into notes.

## Pairing With Other Skills

- `/recon`: discovers pages, params, tech, and initial JS URLs.
- `/url-ingest`: aggregates `jsfiles.txt` and tracks reviewed/deep-reviewed
  state.
- `/create-wordlists`: consumes JS-derived route/param/action candidates.
- `/use-wordlists` and `/fuzz`: run generated candidates with scope/rate/fuzz
  history controls.
- `/xss` and `/dom-xss`: consume source-to-DOM-sink, route/reflection,
  hidden-state, postMessage, storage, and navigation leads.
- `/ssrf`: consumes URL fetcher, preview, webhook, importer, embed/codelet,
  favicon, image/media loader, and redirect leads.
- `/sqli`: consumes search/filter/sort/report/export parameter and request-body
  leads.
- `/idor` and `/access-control`: consume object IDs, tenant/team/project IDs,
  role names, workflow states, permission-related endpoints, and ownership
  transition flows.
- `/ato` and `/password-reset`: consume login, recovery, invite, identity,
  OAuth/SSO, captcha/risk, and session-binding flows.
- `/payment-testing`: consumes checkout, coupon, invoice, subscription, refund,
  entitlement, and pricing flows.
- `/analyze-endpoint`: turns a JS-discovered request shape or proxy request into
  a reusable endpoint contract.

## Output Contract

Every meaningful JS run should leave:

- `manifest.json`: inputs, run id, counts, and output paths
- `metadata.jsonl`: one row per downloaded JS body
- `packets.jsonl`: packet/chunk map for agent review
- `_library/ledger.json`: URL aliases, file hashes, artifact paths, and chunk
  set metadata
- packet markdown files used by agents
- notes/handoff if a human or future agent should continue
- `/url-ingest` coverage marks for inventory and deep review

## Exit Checklist

- Large JS bodies stayed on disk, not in chat.
- Existing URL aliases, file hashes, and chunk sets were reused unless
  `--refresh` was intentional.
- Agent packets were bounded and page-context aware.
- Cheap signals were treated as leads, not confirmed findings.
- Reviewed chunks produced structured outputs.
- Coverage was marked so future agents do not repeat the same depth pass.
- Wordlist and vuln-lane handoffs were routed to the owning skills.
