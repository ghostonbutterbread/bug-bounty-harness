---
name: xss
description: Use when testing Cross-Site Scripting or routing XSS work into reflected, stored, or DOM lanes. Load this first for XSS triage, then load reflected-xss, stored-xss, or dom-xss based on where attacker-controlled input lands.
---

# XSS Router

Use this as the XSS routing card. It should classify the XSS shape, load the
right lane skill, and keep payload choice tied to the actual render context.

Core posture: XSS testing is controlled rule-breaking. Be creative with payload
shape, encodings, parser confusion, sanitizer breakouts, framework quirks, and
browser/server differences. Be conservative with impact, ownership, rate,
cleanup, and human-visible side effects.

Do not treat a blocked payload as a dead lane when signal exists. Reflection,
DOM reachability, sanitizer interaction, browser/server render differences,
stored re-rendering, or unusual encoding all mean the lane is at least `warm`
and should enter pressure mode.

## Required Preflight

Follow the Cold-Start Doctrine from `agents/index.md`:

1. **Scope Gate** — Check `~/Shared/scopes/{program}/` first, then
   `~/Shared/bounty_recon/{program}/scope/`. If no scope exists, try
   `/pullscope`. If the program has no published scope, write `no scope` stub.
2. **Cold Surface Pass** — Look at the target URL/parameter with fresh eyes.
   Send an inert marker, observe where it lands, classify the render context.
   Do NOT query MapStore or prior attempts yet.
3. **Novelty Quota** — Identify 3-5 fresh parameters, sinks, render contexts,
   or input vectors from direct observation before pulling prior state.
4. **Memory Overlay** — Now read shared state in this order when the files
   exist:
   - `notes/summary.md`
   - `notes/observations.md`
   - `checklist.md` (XSS items only)
   - `todo.md` (XSS items only)
   Then query MapStore and prior attempts for the concrete URL, parameter,
   render context, or sink the agent found. Use prior results to rebound from
   known boundaries and avoid duplicates, not to choose the first target.

Also load:

- `general-security-testing-policy`
- `live-testing-policy`
- `injection-testing-policy` once a render sink, stored render point, DOM sink,
  sanitizer, markdown/HTML parser, or browser/server parser boundary is
  plausible
- `waf-live-policy` when payloads are blocked, filtered, normalized, challenged,
  or mutated

## Route Selection

Load the smallest matching lane:

| Signal | Load | Why |
| --- | --- | --- |
| Marker appears in the immediate HTTP response | `reflected-xss` | Immediate render/context breakout and browser proof. |
| Marker is saved and appears later in another view, notification, admin page, email, export, or feed | `stored-xss` | Persistence, render-point discovery, cleanup, and blast-radius control. |
| Marker reaches client-side sources/sinks such as URL, hash, storage, `postMessage`, router state, or JS-generated HTML | `dom-xss` | Browser source-to-sink verification and framework behavior. |
| More than one is plausible | Load all relevant lanes, but keep notes separated by lane. |

Do not treat these lanes as mutually exclusive. A stored value can become DOM
XSS at render time; a reflected value can be inert in raw HTML but exploitable
after client-side parsing; a DOM route can also call server APIs.

## Shared Payload Sources

Use context-specific payloads, not generic spraying. Start with the shared
payload-selection reference:

- `skills/xss/references/payload-selection.md`

Useful local sources:

- `/home/ryushe/projects/bug_bounty_harness/prompts/xss-playbook.md`
- `/home/ryushe/projects/bug_bounty_harness/prompts/xss-payloads.md`
- `/home/ryushe/Shared/word_lists/xss/payloads.txt`
- `/home/ryushe/.axss/knowledge.db` when curated rows exist

## Discovery And Mapping Tools

Use Dalfox and Dursgo as XSS discovery and application-mapping helpers before
deep payload work. They should expand the input/sink map, not replace the
context-aware lane workflow.

For deterministic canary source-to-sink mapping, use the local mapper under:

- `skills/xss/scripts/xss_canary_mapper.py`

The mapper plans inert `GHOST_XSS_*` canaries from URL/tool/source artifacts,
can fetch planned GET canaries with saved program scope or explicit host
allowlists, scans responses for reflections, classifies basic render contexts,
and writes compact `agent_packets/*.md` for XSS lane workers. Use `--offline`
or the `plan`/`scan` commands when you only want artifact processing.

Before using either tool, read:

- `skills/bounty-tools/SKILL.md`
- `skills/xss/references/tool-assisted-discovery.md`

Use Dalfox when the task is parameter-focused:

- Mine hidden query parameters and reflected inputs across URL lists.
- Screen large recon URL batches for reflection, injectable characters, and
  candidate XSS vectors.
- Fingerprint WAF behavior and record blocked/free characters before choosing
  bypass families.
- Emit structured output for follow-up by `xss_framework.py`,
  `xss_hunter.py`, `reflected-xss`, or `dom-xss`.

Use Dursgo when the task is application-mapping focused:

- Crawl an app or route cluster to discover URLs, forms, endpoints, and hidden
  parameters.
- Use JavaScript rendering for SPA/DOM-heavy surfaces where raw HTTP misses
  browser-created routes or sinks.
- Run authenticated sweeps when cookies, bearer tokens, or custom headers are
  available and in scope.
- Treat `xss-reflected`, `xss-stored`, and `domxss` output as triage leads that
  still need lane-specific context classification and browser verification.

Recommended routing:

1. Recon URL list or many unknown parameters: run Dalfox first for parameter
   mining and reflection screening.
2. SPA, route cluster, or auth-protected app area: run Dursgo first for crawling,
   JavaScript-rendered mapping, and broad XSS candidate discovery.
3. Feed candidate parameters, URLs, sinks, WAF clues, and JSON reports into the
   normal XSS working loop.
4. Record tool-derived leads as `Potential` until a lane worker proves source,
   sink/context, and browser execution.

## Harnesses

Use `agents/xss_framework.py` for broad XSS work. It handles discovery,
reflection screening, reflected/stored/DOM lanes, and optional browser
verification.

```bash
python /home/ryushe/projects/bug_bounty_harness/agents/xss_framework.py \
  --target https://target.example/search?q=test \
  --program target \
  --mode full \
  --rate-limit 2
```

Use `agents/xss_hunter.py` for narrower parameter-focused passes.

```bash
python /home/ryushe/projects/bug_bounty_harness/agents/xss_hunter.py \
  --target https://target.example/search?q=test \
  --program target \
  --depth deep \
  --rate-limit 5
```

## Working Loop

1. Identify the input vector: query, path, body, JSON, header, cookie, upload,
   stored object field, router state, storage, or message.
2. Send an inert marker and record where it lands.
3. Classify the render context before choosing payloads.
4. Query MapStore and prior attempts for this URL, surface, parameter, and
   render context.
5. Load `reflected-xss`, `stored-xss`, or `dom-xss`.
6. Use the lane skill to pick payload families, browser proof, cleanup, and
   report shape.
7. Escalate to `waf-live-policy` and bypass/mutation work when filtering or
   parsing behavior becomes the interesting surface.

## Pressure Mode

Every deliberate probe should write an attempts row in the run's attempts
directory. Record the exact payload, payload family, encoding, why that payload
matched the context, observed transform, browser result, block reason, and next
mutation.

Use this state model:

- `cold`: no reflection, storage, source-to-sink, sanitizer, or browser signal.
- `warm`: marker reflects, persists, reaches DOM, hits a sanitizer, or changes
  browser/server output but execution is not proven.
- `hot`: attacker-controlled bytes influence a dangerous context, sanitizer
  decision, URL, script/JSON island, DOM sink, or stored render path.
- `exhausted`: representative families failed and the render/parser boundary is
  understood.

Only pivot automatically from `cold` or `exhausted`. If the lane is `warm` or
`hot`, keep pressure on the same vector with context-matched mutation families
until the block is understood or policy/safety stops the next probe.

Typical XSS pressure ladder:

1. marker reflection or source-to-sink proof
2. render context classification
3. dangerous character matrix for `<`, `>`, `"`, `'`, backtick, slash, equals,
   colon, parentheses, whitespace, and newline
4. transform check: encoded, stripped, normalized, decoded once/twice,
   sanitized, re-rendered, or moved between server and browser
5. family queue: text breakout, attribute breakout, tag breakout, URL scheme,
   markdown, JSON/script string, DOM reparse, storage/postMessage, sanitizer
   bypass
6. browser proof, residual next probe, or exact kill reason

Do not summarize the lane as "blocked" without saying which families were
tried, what blocked them, what evidence proves the block, and whether any
source/sink remains unexplored.

## Deep Default For Hybrid And Deep-Hunt

For `/hybrid`, `/deep-hunt`, URL-batch, or route-cluster runs, XSS workers must
default to source-to-sink mapping before payload volume. The goal is to explain
why a payload family matches the observed sink, not to spray generic payloads.

Required sequence:

1. Inventory sources: query, hash, path/router params, URLSearchParams,
   `location`, storage, `postMessage`, data islands, API responses, and any
   framework state that can carry attacker-controlled bytes.
2. Inventory sinks: reflected HTML, input/attribute/text nodes, JSON/bootstrap
   blobs, script/data islands, `innerHTML`/`outerHTML`/`insertAdjacentHTML`,
   URL-bearing attributes, iframe/embed HTML, framework raw-HTML helpers, and
   sanitizer trust-bypass helpers.
3. Record framework and edge clues before payload choice: React/Vue/Angular,
   router, hydration/state libraries, bundle names, CSP, WAF/challenge signal,
   and browser-vs-raw response differences.
4. Choose payload families from the context: attribute breakout, tag breakout,
   URL-scheme, template-literal, JSON/XML/iframe-attribute, DOM-source, hash,
   storage, or `postMessage`.
5. Track every deliberate probe in `attempts.jsonl` with payload family,
   source, sink/context, encoding/normalization result, browser result, and
   stop reason. If no execution occurs, record the exact boundary.

Do not mark an XSS lane complete from raw HTTP alone when browser-only routing,
Cloudflare/challenge behavior, or framework rendering is material to the route.
Do not continue increasing payload count after a representative set proves the
context is inert; switch to a new source/sink hypothesis or stop.

## Evidence Standard

Record:

- full URL and request method
- auth state and account/resource ownership
- exact vector and parameter/header/body field
- context where input landed
- exact payloads or canaries tried, with payload family and encoding
- payload family and why it matched that context
- observed transform and block reason
- browser verification status
- interaction needed, if any
- attempts artifact path and MapStore pointer
- cleanup state for stored payloads
- pressure state and next discriminating probe

## Status Rules

- `Confirmed`: JavaScript execution occurred in a browser or equivalent checker.
- `Likely`: source, sink, and context are strong but browser execution is blocked.
- `Potential`: controllable reflection/storage/source-to-sink exists, but the
  exploit path is not proven.
- `False positive`: the value is inert, safely encoded, unreachable, or blocked
  in the tested context.
