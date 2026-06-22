# Focused Recon Playbook

## Purpose

Focused recon turns broad recon output into a ranked, human-readable map. It
answers:

- What hosts are worth looking at first?
- What does each host appear to do?
- Which URLs, parameters, JavaScript files, ports, and auth boundaries matter?
- Which specialist lane should pick up the next step?
- What has already been checked?

It should make a program easier to start, not create another noisy dump.

## Source Inputs

Prefer current aggregate and enrichment artifacts:

```text
~/Shared/web_bounty/<program>/web/recon/aggregated/
├── urls.txt
├── alive.txt
├── params.txt
└── jsfiles.txt

~/Shared/web_bounty/<program>/web/recon/recon-ry/**/runs/**/
├── httpx.jsonl
├── hosts.jsonl
├── ips.txt
├── naabu.jsonl
├── ports.txt
├── waf_hosts.txt
├── unprotected_hosts.txt
└── review_queue.jsonl
```

Also consume, when present:

- `parameter_mining/`
- `js/_library/`
- proxy-store summaries
- `live-map/`
- `hunter-memory/`
- manual recon notes

Do not paste large files into prompts. Read them locally, summarize, and write
compact outputs under `map/`.

## Map Directory Contract

Focused recon writes to:

```text
~/Shared/web_bounty/<program>/web/recon/map/
```

The top level is the current curated view:

```text
map/
├── README.md                    # how to use this map and latest run id
├── host_cards.jsonl             # one host per row
├── route_clusters.jsonl         # normalized route groups
├── endpoint_map.jsonl           # selected source-attributed endpoints
├── lane_queues/
│   ├── api.txt
│   ├── auth.txt
│   ├── stage-dev.txt
│   ├── js-config.txt
│   ├── file-workflows.txt
│   ├── object-ids.txt
│   ├── ops-debug.txt
│   └── waf-403.txt
├── target_packets/
│   └── <host>.md
├── handoffs/
│   ├── js.md
│   ├── api.md
│   ├── auth.md
│   ├── fuzz.md
│   ├── 403.md
│   └── deep-hunt.md
├── gf/
│   ├── pattern-sources.md
│   └── candidate-promotions.md
├── _meta/
│   ├── manifest.json
│   ├── RUN_INDEX.md
│   └── scoring.md
└── _runs/<run-id>/              # timestamped snapshots and scratch outputs
```

If multiple runs happen, update current top-level files and add a timestamped
snapshot under `_runs/<run-id>/`.

## Host Cards

Write one JSON object per host:

```json
{
  "host": "labs.example.com",
  "score": 75,
  "source_files": ["aggregated/urls.txt", "recon-ry/.../httpx.jsonl"],
  "sample_urls": ["https://labs.example.com/", "https://labs.example.com/api"],
  "ports": ["80/tcp", "443/tcp"],
  "status": [302, 401],
  "tech": ["CloudFront", "Okta"],
  "auth_boundary": "redirects-to-sso",
  "waf_cdn": ["cloudfront"],
  "signals": ["stage-dev", "api", "auth", "js-config"],
  "lanes": ["js", "auth", "403", "fuzz"],
  "next_action": "Build target packet and crawl/JS-inventory before bypass testing."
}
```

Score is a sorting hint, not proof.

## Scoring Signals

Boost:

- `stage`, `staging`, `dev`, `test`, `demo`, `labs`, `preview`, `sandbox`,
  `beta`, `internal`, `ci`
- API surfaces: `/api`, `/_ajax`, `/graphql`, `/openapi`, `/swagger`, `/rpc`
- auth surfaces: `login`, `oauth`, `sso`, `saml`, `mfa`, `callback`,
  `redirect`, `invite`, `reset`, `session`
- JavaScript/config exposure: `_next/static`, chunk files, `env.js`,
  `config.json`, `asset-manifest.json`, `service-worker.js`, source maps
- file/workflow surfaces: `upload`, `import`, `export`, `download`, `media`,
  `avatar`, `document`, `image`, `render`, `preview`
- object/workspace terms: `user`, `team`, `org`, `brand`, `design`, `folder`,
  `workspace`, `tenant`, `group`, `account`
- status/ops surfaces: `status`, `health`, `ready`, `metrics`, `debug`,
  `config`, `version`
- 401/403/405 responses or route clusters
- interesting Naabu ports, especially when they differ from the normal web
  surface

Deprioritize:

- pure marketing pages
- duplicate locale/tracking URLs
- static assets with no new endpoints or manifests
- third-party hosts unless explicitly in scope

Do not exclude WAF/CDN hosts. Use WAF/CDN as context for choosing browser,
header, path, 403, or rate-aware lanes.

## GF-Style Lenses

Focused recon uses GF-style pattern packs as reusable lenses. The patterns
should be config-backed so humans and agents grep the same way.

Initial packs:

- `stage-dev`: `stage`, `staging`, `dev`, `test`, `demo`, `labs`, `preview`,
  `sandbox`, `beta`, `internal`, `ci`, `uat`, `qa`
- `api`: `/api`, `/_ajax`, `/graphql`, `/openapi`, `/swagger`, `/rpc`, `/v1`,
  `/v2`, `/rest`, `/internal`
- `auth`: `login`, `oauth`, `oauth2`, `sso`, `saml`, `mfa`, `session`,
  `callback`, `redirect`, `return`, `next`, `invite`, `reset`, `magic`
- `object-ids`: `userId`, `user_id`, `teamId`, `orgId`, `brandId`,
  `designId`, `folderId`, `workspaceId`, `tenantId`, `accountId`, UUID paths
- `file-workflows`: `upload`, `import`, `export`, `download`, `media`,
  `avatar`, `image`, `document`, `attachment`, `render`, `preview`
- `ops-debug`: `admin`, `staff`, `debug`, `trace`, `config`, `env`, `status`,
  `health`, `metrics`, `ready`, `version`
- `js-config`: `env.js`, `config.json`, `asset-manifest.json`,
  `service-worker.js`, `_next/static`, `static/js`, `chunk`, `.map`
- `waf-403`: 401/403/405 URLs, encoded path normalization, method/header
  candidates, forbidden API/static/config routes

New observed patterns should first go to:

```text
map/gf/candidate-promotions.md
```

Promote only stable, reusable patterns into the shared pack after review.

## Lane Queues

Each queue is a sub-list of full URLs or route templates:

```text
map/lane_queues/api.txt
map/lane_queues/auth.txt
map/lane_queues/stage-dev.txt
map/lane_queues/js-config.txt
map/lane_queues/file-workflows.txt
map/lane_queues/object-ids.txt
map/lane_queues/ops-debug.txt
map/lane_queues/waf-403.txt
```

Each queue should be small enough for an agent to read and start. If the raw
match set is huge, keep the raw count in `_meta/manifest.json` and write only
ranked examples to the queue.

## Target Packets

Create one packet per selected host:

```text
map/target_packets/<host>.md
```

Packet sections:

- Summary: what the host likely does
- Evidence: source files, counts, status, title, redirects, tech, ports
- Auth boundary: public, SSO redirect, 401, 403, mixed, unknown
- Route clusters: top route families and weird paths
- JavaScript/config: scripts, manifests, chunks, source maps, config files
- Parameters and object IDs
- Lane queues hit
- Safe first actions
- Already tried
- Stop conditions

## Child Work

Focused recon can dispatch or brief child lanes after a target packet exists.

Useful dispatches:

- `/js` for JS/config/chunk/source-map analysis
- `/parameter-mining` for parameter/field extraction
- `/intelligent-fuzzing` for small targeted endpoint mining
- `/403`, `/headers`, `/bypass`, `/error-triage` for 401/403/405 boundaries
- `/auth`, `/ato`, `/jwt-auth`, `/access-control`, `/idor` for auth or object
  boundary leads
- `/deep-hunt` for one host or route cluster needing slow mapping
- `/live-map` when browser/proxy exploration is needed

Do not ask one child to test every vulnerability class. Give one host, one
lane, one objective, and one stop condition.

## Background Nmap / Service Recon

Naabu output can justify deeper service recon, but keep it bounded:

- only selected high-signal hosts or IPs
- use conservative timing
- no broad network sweeps
- prefer service/version confirmation over vulnerability scripts
- record the command, rate/timing, host/IP list, and reason in the target packet

Run background Nmap only when the port set suggests more than ordinary web
traffic or when Ryushe explicitly wants service-depth on that target.

## CVE / Tech Lookup

Use CVE/advisory lookup as enrichment, not speculation.

Good inputs:

- concrete product and version
- server/banner/version from Nmap or headers
- JS package version in a downloaded bundle or source map
- framework/library version from deterministic evidence

Weak inputs:

- generic CDN names
- cloud provider only
- WAF product only
- marketing page technology guesses

If the signal is concrete, create an `/intel` or CVE handoff. Otherwise record
the tech as context and keep mapping.

## Canva Trial Shape

For Canva-like recon data:

1. Start from `web/recon/aggregated/` plus latest `recon-ry` enrichment run.
2. Build `map/host_cards.jsonl`.
3. Prioritize:
   - `labs`, `docs`, `docsdemo`, `pipeline-signing`, `playroom`, `test`, `ui`
   - file/export/media hosts such as `document-export`, `media-public`,
     `media-private`, `mockup-assets`, `static-cse`
   - API/auth hosts such as `api`, `www/_ajax`, Okta callback routes
   - separate Shopify/payment hosts into payment/business-logic lanes
4. Create target packets for the top 5-10 hosts.
5. Build handoffs for `/js`, `/403`, `/api`, `/auth`, `/fuzz`, and `/deep-hunt`.

## Safety

Use low rates and target-owned/scoped hosts only. Do not perform policy-limit
testing. Stop before account lockout, CAPTCHA escalation, destructive actions,
non-owned private data, or unapproved credential use.

## Completion Standard

A focused recon pass is useful when the next agent can answer:

- where do I start?
- why is this host interesting?
- what routes and files matter?
- which lane owns the next step?
- what has already been checked?
- where do I write results back?
