# Parameter Mining Playbook

## Purpose

Build source-attributed parameter coverage for a program, then convert that
coverage into bounded fuzzing queues and vuln-lane handoffs.

This workflow is useful when `params.txt` is endpoint-heavy but parameter-light:
the app has many URLs, JavaScript files, proxy-observed requests, or tool
artifacts, but not enough known query/body/header fields to test meaningfully.

## Principles

- Preserve raw artifacts first, then extract safe summaries.
- Keep source-separated packs so agents know why a parameter exists.
- Prefer observed parameters over generated guesses.
- Generate variants from target naming conventions, not generic spray lists.
- Fuzz only scoped endpoints with explicit rate, filters, and history logging.
- Do not store secret values, raw cookies, bearer tokens, passwords, or private
  payloads in parameter packs.

## Run Layout

Use a UTC run id such as `parameter-mining-20260618T203000Z`.

```text
~/Shared/web_bounty/<program>/web/recon/parameter_mining/<run-id>/
├── manifest.json
├── parameters.jsonl
├── notes.md
├── queue/
│   ├── xss-url-patterns.txt
│   ├── ssrf-url-patterns.txt
│   ├── sqli-url-patterns.txt
│   └── recon-hidden-param-patterns.txt
└── handoffs/
    ├── xss.md
    ├── ssrf.md
    ├── sqli.md
    ├── idor-access-control.md
    └── recon.md
```

`queue/` files are run artifacts, not canonical lane lists. The canonical flat
pool is still `web/recon/aggregated/params.txt`. Prefer dynamic filters such as
GF over persistent lane-specific packs:

```bash
cat ~/Shared/web_bounty/<program>/web/recon/aggregated/params.txt | gf xss
cat ~/Shared/web_bounty/<program>/web/recon/aggregated/params.txt | gf ssrf
```

Use queued files only when a campaign needs reproducible evidence, long-running
tool input, or performance caching.

## Phase 1 - Resolve Inputs

Read the aggregate recon directory first:

```text
~/Shared/web_bounty/<program>/web/recon/aggregated/
```

Use these files when present:

- `params.txt` and `params_raw.txt` for already parameterized URLs
- `urls.txt` and `alive.txt` for endpoint patterns that may accept hidden params
- `jsfiles.txt` for JavaScript inventory handoff
- `dirs.txt` for route nouns and app vocabulary

Then check additional local sources:

- JavaScript library metadata under `web/recon/js/_library/`
- proxy store summaries from `/chromium-test`, Hoster MITM lanes, or approved
  Ryushe proxy shape pulls
- `/analyze-endpoint` outputs, especially `parameters.json`
- tool output directories from Dalfox, Arjun, kxss, ParamSpider, LinkFinder,
  Katana, hakrawler, GauPlus, Wayback, or recon-ry
- OpenAPI, Swagger, GraphQL, sitemap, robots, docs, and public forms

Record missing sources in `notes.md` instead of failing the run.

## Phase 2 - Extract Observed Parameters

Extract and dedupe parameter names by location:

- query string keys
- JSON/form/XML body keys
- header names that affect app behavior
- cookie names, redacted to name only
- path variables and route IDs
- hash/router state keys
- GraphQL operation names, variables, and fields
- HTML form fields, hidden inputs, `data-*` attributes, and hydration state keys

For each candidate row, write JSONL with:

```json
{"name":"redirect_uri","location":"query","source":"javascript","source_ref":"packet:abc123","confidence":"observed","value_shape":"url","lane_hints":["ssrf","open-redirect","xss"],"example_urls":["https://target.example/login?redirect_uri=/home"]}
```

Use full URLs only when they are in scope and do not contain secrets. Otherwise
store route templates and source references.

## Phase 3 - Generate Target Variants

Generate variants only after observed candidates establish naming conventions.

Useful transforms:

- case style: `userId`, `user_id`, `user-id`, `userid`
- boolean toggles: `debug`, `debugMode`, `isDebug`, `enableDebug`
- resource ids: `user`, `userId`, `uid`, `accountId`, `workspaceId`
- URL sinks: `url`, `uri`, `next`, `return`, `returnTo`, `callback`,
  `redirect`, `redirect_uri`, `webhook`, `image`, `avatar`, `feed`, `source`
- access-control fields: `role`, `scope`, `permission`, `tenant`, `owner`,
  `team`, `organization`, `entitlement`, `plan`
- request-shape fields: `format`, `fields`, `include`, `expand`, `sort`,
  `order`, `filter`, `limit`, `offset`, `page`, `cursor`

Keep generated variants in a separate pack. Do not mix them with observed
parameter names.

## Phase 4 - Classify Lanes

Assign `lane_hints` from source and shape:

- XSS: reflected params, DOM-consumed router/hash/query keys, callback/jsonp,
  search, title, message, name, html, markdown, description
- SSRF/open redirect: URL, URI, callback, webhook, import, image, avatar,
  preview, feed, redirect, next, return, returnTo
- SQLi: search, query, filter, sort, order, where, id, category, status,
  report, table, column, field
- IDOR/access-control: user, account, tenant, org, workspace, project, design,
  folder, team, owner, role, scope, permission, resource IDs
- LFI/path: file, path, template, theme, lang, locale, download, attachment
- recon/request-shape: format, include, expand, fields, debug, preview, beta,
  feature flags

Use lane hints to prioritize agents; do not treat a name match as proof of a
vulnerability.

Dynamic matcher output should be stored as evidence or test metadata, not as a
second source of truth. A GF hit means "this parameter should enter the XSS
review queue"; the canonical test result belongs in `/url-ingest`.

## Phase 5 - Build Fuzz Queues

For endpoint patterns, prefer:

- endpoints already observed accepting parameters
- endpoints in the same route cluster as observed params
- endpoints loaded by JavaScript that constructed related params
- API routes with `GET`, search, filter, import, preview, or render behavior
- authenticated owned-account endpoints when the lane requires account context

Queue files should contain full URL patterns with a single `FUZZ` marker when
possible:

```text
https://target.example/api/search?FUZZ=ghostprobe
https://target.example/render?existing=1&FUZZ=ghostprobe
```

For body/header fuzzing, write a handoff packet instead of forcing everything
into a URL file.

## Phase 6 - Active Probing

Before any active probing:

1. Confirm scope and account/resource ownership.
2. Check `/url-ingest next` for prior URL, route, and parameter-level coverage.
3. Load `/fuzz` and `/use-wordlists`.
4. Use explicit rate limits and stable filters.
5. Record the run in fuzz history.

Suggested low-rate query parameter discovery:

```bash
ffuf -u 'https://target.example/api/search?FUZZ=ghostprobe' \
  -w packs/generated-variants.txt \
  -mc all -fc 404 -rate 3 -c -v
```

Suggested Arjun-style run for a bounded endpoint set:

```bash
arjun -i queue/recon-hidden-param-patterns.txt \
  --rate-limit 2 -t 2 -d 0.5 -T 10 --disable-redirects --stable \
  -o arjun.json -oT arjun.txt
```

Suggested Dalfox handoff is XSS-only and should start from scoped URL patterns:

```bash
dalfox file queue/xss-url-patterns.txt \
  --skip-bav --silence --only-discovery
```

Do not run tool defaults blindly. Keep scope, rate, auth state, and output paths
explicit.

## Phase 7 - Handoffs And Coverage

Write compact handoff packets with:

- candidate parameter names and source counts
- strongest example URLs or route templates
- source artifacts to inspect
- why the lane is plausible
- what has already been tested
- exact next command or child-agent assignment

Then:

- ingest URL-shaped outputs through `/url-ingest`
- mark tested lane/status after active runs; include `--param <name>` when the
  review was parameter-specific
- route concrete signals to `/xss`, `/ssrf`, `/sqli`, `/idor`,
  `/access-control`, `/lfi`, or `/request-exploration`
- add reusable generic names to the global wordlist repo only when they are not
  target-private

Examples:

```bash
python3 agents/url_ingest.py params <program> --lane ssrf --untested --limit 25

python3 agents/url_ingest.py next <program> \
  --lane ssrf --skill gf --test-family dynamic-filter --param url --limit 25

python3 agents/url_ingest.py mark <program> \
  --url "https://target.example/import?url=https://example.com" \
  --lane ssrf --status surface_reviewed \
  --skill gf --test-family dynamic-filter --param url \
  --technique url-shaped-param-review \
  --notes "Observed as URL-shaped param; queued for owned-callback SSRF check."
```

## Agent Split Pattern

For a broad target, split child agents by source:

- JS miner: extracts route/query/body/header/form names from JavaScript packets
- Proxy miner: extracts sanitized shape-only params from proxy stores
- Tool-output miner: normalizes Dalfox/Arjun/kxss/ParamSpider/etc. output
- Classifier: merges, dedupes, scores, and writes lane packs
- Fuzz runner: runs one bounded queue through `/fuzz` and records coverage

Each child should return artifact paths and counts, not raw giant lists.
