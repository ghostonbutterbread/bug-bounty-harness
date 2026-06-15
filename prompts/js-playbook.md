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
├── packets.jsonl
└── packets/<sha-prefix>-NNN.md

~/Shared/web_bounty/<program>/web/recon/js/_library/
├── ledger.json
├── downloads/<sha256>.js
└── chunks/<sha256>/<chunk-set-key>/
    ├── manifest.json
    └── NNN.js
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
- extract cheap signals: URLs, API paths, params, imports, source maps,
  source/sink keywords, framework/router clues, GraphQL operations, route hints,
  interesting object/request keys, and flow categories
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
  --refresh
```

Without `--refresh`, the helper reuses the URL-to-hash ledger and avoids another
download when the artifact is already present.

## Agent Deep Review

Agents consume packet files, not raw program-wide bundle lists.

Review goals per packet:

- What application area does this JS support?
- What endpoints, params, request fields, GraphQL operations, or action names
  does it reveal?
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
- If a suspicious function is only partly visible in one chunk, use
  `packets.jsonl` and the chunk-set manifest to inspect adjacent chunks from the
  same file hash before finalizing the review.

## Signal Priority

High-value JS analysis is flow-first, not secret-first.

Prioritize:

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
- third-party service identifiers and API keys only when they plausibly expand
  reachable scope or unlock a real integration path

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

## Pairing With Other Skills

- `/recon`: discovers pages, params, tech, and initial JS URLs.
- `/url-ingest`: aggregates `jsfiles.txt` and tracks reviewed/deep-reviewed
  state.
- `/create-wordlists`: consumes JS-derived route/param/action candidates.
- `/use-wordlists` and `/fuzz`: run generated candidates with scope/rate/fuzz
  history controls.
- `/xss` and `/dom-xss`: consume source-to-DOM-sink and route/reflection leads.
- `/ssrf`: consumes URL fetcher, preview, webhook, importer, and media loader
  leads.
- `/sqli`: consumes search/filter/sort/report/export parameter leads.
- `/idor` and `/access-control`: consume object IDs, tenant/team/project IDs,
  role names, workflow states, and permission-related endpoints.
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
