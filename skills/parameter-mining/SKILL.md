---
name: parameter-mining
description: Mine parameter names, request fields, and endpoint shapes from JavaScript, proxy history, aggregate recon files, and parameter-mining tool output, then route source-attributed candidates into wordlists, URL ingest, and vuln-lane fuzzing.
---

# Parameter Mining

Use `/parameter-mining` when the goal is to expand parameter coverage before
XSS, SSRF, SQLi, IDOR, open-redirect, LFI, or request-shape testing.

This skill is a router and evidence combiner. It does not replace `/js`,
`/create-wordlists`, `/url-ingest`, `/use-wordlists`, `/fuzz`, or
`/intelligent-fuzzing`; it coordinates them into a parameter-first workflow.

## Load Order

1. Read
   `/home/ryushe/projects/bug_bounty_harness/prompts/parameter-mining-playbook.md`.
2. Read current aggregate state:
   `~/Shared/web_bounty/<program>/web/recon/aggregated/`.
3. Check `/url-ingest brief <program>` and existing lane coverage before
   assigning agents or fuzzing.
4. Load `/js` for JavaScript-derived parameters.
5. Prefer dynamic filters over permanent lane packs. Use GF or another pattern
   matcher as a pipe over `aggregated/params.txt` when the lane is known.
6. Load `/fuzz` and `/use-wordlists` before any active parameter probing.

## Canonical Sources

Prefer source-attributed ingestion from:

- aggregate recon files: `urls.txt`, `params_raw.txt`, `params.txt`,
  `jsfiles.txt`, `dirs.txt`, `alive.txt`
- JavaScript inventory and generated observations
- centralized proxy stores and Ryushe proxy shape summaries
- `/analyze-endpoint` request contracts and `parameters.json`
- Dalfox, Arjun, kxss, ParamSpider, LinkFinder, Katana, hakrawler, and similar
  tool outputs
- forms, hidden inputs, `data-*` attributes, hydration JSON, GraphQL queries,
  OpenAPI/Swagger docs, and sitemap/robots-derived routes

Treat proxy and tool outputs as evidence. Do not persist raw cookies, bearer
tokens, passwords, private request bodies, or secret values into packs, notes,
or prompts.

## Output Contract

Write target-specific artifacts under:

```text
~/Shared/web_bounty/<program>/web/recon/parameter_mining/<run-id>/
```

Each run should produce:

- `manifest.json` - inputs, tools, source paths, counts, scope mode, timestamp
- `parameters.jsonl` - one candidate per row with source, location, confidence,
  examples, and lane hints
- `queue/*.txt` - optional run-specific endpoint patterns ready for bounded
  fuzzing
- `handoffs/*.md` - compact packets for XSS, SSRF, SQLi, IDOR, and recon agents
- `notes.md` - proxy availability, skipped sources, caveats, and next actions

Do not treat generated lane files as canonical. `aggregated/params.txt` remains
the flat global pool; GF, Dalfox, kxss, Arjun, and custom matchers should act as
dynamic filters over that pool unless a run needs a reproducible queue artifact.

## Candidate Fields

Every durable candidate should keep enough context for later agents:

- `name` - parameter, field, header, cookie, GraphQL field, or route variable
- `location` - query, body, header, cookie, path, hash, graphql, html, js
- `source` - aggregate file, JS packet, proxy request, tool output, docs, form
- `source_ref` - local file path, request id, packet id, or tool artifact path
- `example_urls` - full URLs when safe and in scope
- `example_routes` - route templates when full URLs are not safe to store
- `value_shape` - boolean, enum, URL, path, object id, JSON, callback, unknown
- `lane_hints` - xss, ssrf, sqli, idor, access-control, open-redirect, lfi
- `confidence` - observed, inferred, generated, or tool-suggested

## JavaScript Lens

When `/js` feeds this skill, ask for:

- `URLSearchParams`, query builders, router params, hash state, and form field
  names
- fetch/XHR/Apollo/GraphQL clients and request body keys
- object keys near API clients, serializers, validators, and feature flags
- URL-bearing names such as `url`, `uri`, `callback`, `redirect`, `next`,
  `returnTo`, `image`, `avatar`, `webhook`, `import`, `source`, and `feed`
- security-sensitive fields such as `role`, `admin`, `permission`, `tenant`,
  `workspace`, `owner`, `plan`, `price`, `coupon`, and `debug`
- hidden state in HTML, hydration globals, `data-*` attributes, and disabled
  controls referenced by JavaScript

Keep raw bundles out of prompts. Store extracted candidates and compact packet
references instead.

## Handoffs

Route candidates by evidence, not just name:

- URL-fetch or callback-shaped params -> `/ssrf`
- reflected or DOM-consumed params -> `/xss`, then reflected/stored/DOM lane
- SQL-like filters, sort/order/search fields -> `/sqli`
- object ids, tenant/workspace/user/resource fields -> `/idor` or
  `/access-control`
- file/path/template fields -> `/lfi` or `/ssti`
- redirect/return params -> `/bypass` or the relevant open-redirect workflow
- unknown but promising fields -> `/intelligent-fuzzing` then
  `/request-exploration`

Before active testing, query `/url-ingest next` with the right lane, skill, test
family, and `--param` when the task is parameter-specific. After testing, mark
the lane result with the same parameter key so future agents do not repeat that
parameter campaign:

```bash
cat ~/Shared/web_bounty/<program>/web/recon/aggregated/params.txt | gf xss

python3 /home/ryushe/projects/bug_bounty_harness/agents/url_ingest.py next <program> \
  --lane xss --skill gf --test-family dynamic-filter --param q

python3 /home/ryushe/projects/bug_bounty_harness/agents/url_ingest.py mark <program> \
  --url "https://target.example/search?q=test" \
  --lane xss --status surface_reviewed \
  --skill gf --test-family dynamic-filter --param q \
  --notes "GF xss match reviewed; no reflection observed."
```
