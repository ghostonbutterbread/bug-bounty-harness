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

1. Read `prompts/js-playbook.md`.
2. Resolve inputs from a page URL, `aggregated/jsfiles.txt`, proxy history,
   recon output, Wayback, or source maps.
3. Use `agents/js_analyzer.py inventory` to download, hash, dedupe, cheaply
   parse, and chunk JavaScript into agent packets.
4. Deep-review selected packets with page/flow context.
5. Record coverage through `/url-ingest` and write durable notes/handoffs.
6. Send generated candidates to `/create-wordlists`, `/use-wordlists`, `/fuzz`,
   or vuln-specific skills such as `/xss`, `/ssrf`, `/sqli`, and `/idor`.

Do not paste huge bundles into prompts. Store raw JS locally, pass bounded
packets to agents, and treat regex hits as leads until impact is verified.
When scoped JavaScript references third-party URLs, treat those URLs as
read-only context. Agents may open public pages to understand title,
description, parameters, and integration purpose, but must not fuzz, mutate,
replay, authenticate against, or otherwise test the third-party host unless it
is explicitly in scope.

Downloaded JavaScript is content-addressed under
`~/Shared/web_bounty/<program>/web/recon/js/_library/`. Check the ledger before
redownloading; reuse existing URL aliases, file hashes, and chunk sets unless a
fresh fetch is explicitly requested.
