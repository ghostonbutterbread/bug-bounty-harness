---
name: js
description: Use when analyzing JavaScript bundles, source maps, endpoints, secrets signals, source-to-sink flows, or generating JS-derived wordlist and vuln-lane handoffs.
---

# JavaScript Analysis

Use `/js` for script-first JavaScript inventory and agent-led deep review.

## Modes

- `analyze` - inspect JavaScript for endpoints, params, auth/storage behavior,
  source maps, source-to-sink flows, secrets signals, and framework clues.
- `generate` - turn reviewed JavaScript evidence into route, parameter,
  wordlist, and vuln-lane handoffs.
- `deep` - spend the task budget on selected chunks instead of scanning a huge
  JS list shallowly.

## Workflow

1. Read the canonical playbook at
   `/home/ryushe/projects/bug_bounty_harness/prompts/js-playbook.md`.
2. Resolve inputs from a page URL, `aggregated/jsfiles.txt`, proxy history,
   recon output, Wayback, or source maps. Use `--target-host` as the scope hint;
   it accepts a host, domain, or URL and stores non-matching extracted URLs as
   external context instead of test targets.
3. Use `agents/js_analyzer.py inventory` to download, hash, dedupe, cheaply
   parse, and chunk JavaScript into agent packets.
4. Deep-review selected packets with page/flow context. Require function-level
   tracing: source value, transforms/checks, callers/callees, sink/request/DOM
   effect, controllability, and missing proof.
5. Correlate JS with provenance and proxy evidence when available: page URL or
   document URL that loaded the script, page context, initiator/referrer, Ryushe
   proxy or agent proxy request references, and nearby scoped API requests.
6. Treat provenance/metadata JSONL as the durable evidence logs and
   `js_info.sqlite` as the query/index layer for provenance, JS files,
   URL aliases, packets, chunks, artifact paths, and reviewed observations.
   Prefer DB lookups during analysis, but keep citations tied to JSONL rows and
   packet paths.
7. Record coverage through `/url-ingest`, write surface observations to
   `/map-store` (URL-anchored, tagged with vuln-class prefixes), and write
   durable notes/handoffs.
8. Send generated candidates to `/create-wordlists`, `/use-wordlists`, `/fuzz`,
   or vuln-specific skills such as `/xss`, `/ssrf`, `/sqli`, and `/idor`.

## Analysis Lenses

Use `/js` as the routing layer for JavaScript evidence. Pick one or more lenses
before deep review, then load the owning skill when a packet produces a concrete
lead:

- `general-map`: routes, requests, params, page context, provenance, and notes.
- `secrets`: usable keys, tokens, GitHub/cloud/service identifiers, and leak
  pivots; generic secret words are low value.
- `dom-xss`: source-to-sink traces from URL/storage/message/form/bootstrap state
  into DOM writes, script creation, navigation, or eval-like sinks.
- `access-control` / `idor`: role, permission, tenant, team, workspace, brand,
  design, folder, invite, group, and owner IDs.
- `business-logic`: workflow state, feature gates, entitlement checks, install
  flows, share/publish/import/export controls, and unsafe client assumptions.
- `ssrf-import`: URL importers, preview/fetch resolvers, webhooks, media loaders,
  embeds, favicon fetches, and server-side URL resolution hints.
- `auth-ato`: login, reset, invite, OAuth/SSO, captcha/risk scoring, session,
  recovery, and identity-binding flows.
- `payment`: checkout, coupon, invoice, subscription, refund, entitlement, plan,
  and billing parameter flows.
- `request-shape`: request builders, GraphQL operations, API clients, headers,
  content types, and proxy-observed request contracts.

For a broad review, run the general map first, then split workers by lens. Do
not ask one worker to deeply analyze every lens across every packet.

Do not paste huge bundles into prompts. Store raw JS locally, pass bounded
packets to agents, and treat regex hits as leads until impact is verified.
When scoped JavaScript references third-party URLs, treat those URLs as
read-only context. Agents may open public pages to understand title,
description, parameters, and integration purpose, but must not fuzz, mutate,
replay, authenticate against, or otherwise test the third-party host unless it
is explicitly in scope.
Also look for hidden or non-rendered state consumed by JavaScript, such as
hidden inputs, `data-*` attributes, inline bootstrap JSON, hydration globals,
disabled controls, and feature flags. These are mapping leads until verified
against page HTML/source or proxy-observed responses.
Do not analyze JS as a detached file when provenance exists. Prefer the chain:
JS packet lead -> page/flow that loaded it -> related proxy requests ->
`/analyze-endpoint` request contract -> bounded owned-account test.
The provenance shape is:
`page/flow -> js_url -> sha256 -> chunk_set -> packet -> extracted endpoints -> related proxy requests -> notes/leads`.

Downloaded JavaScript is content-addressed under
`~/Shared/web_bounty/<program>/web/recon/js/_library/`. Check the ledger before
redownloading; reuse existing URL aliases, file hashes, and chunk sets unless a
fresh fetch is explicitly requested.
`--target-host` accepts a URL, host, or parent domain. It controls which JS URLs
are downloaded and which extracted endpoints count as in-scope; other extracted
URLs are still stored as external integration/context artifacts.
Provenance is stored beside it as append-only JSONL plus a generated SQLite
index:
`~/Shared/web_bounty/<program>/web/recon/js/_library/metadata.jsonl`
`~/Shared/web_bounty/<program>/web/recon/js/_library/provenance.jsonl`
`~/Shared/web_bounty/<program>/web/recon/js/_library/observations.jsonl`
`~/Shared/web_bounty/<program>/web/recon/js/_library/js_info.sqlite`
