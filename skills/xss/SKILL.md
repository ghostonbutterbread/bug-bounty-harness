---
name: xss
description: Use when testing Cross-Site Scripting or routing XSS work into reflected, stored, DOM, or blind lanes. Load this first for XSS triage, then load reflected-xss, stored-xss, dom-xss, or blind-xss based on where attacker-controlled input lands.
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

Read `general-security-testing-policy` first and follow its Cold-Start guidance (mirrored in `agents/index.md`):

1. **Scope Gate** — Check `~/Shared/scopes/{program}/` first, then
   `~/Shared/bounty_recon/{program}/scope/`. If no scope exists, try
   `/pullscope`. If the program has no published scope, write `no scope` stub.
2. **Cold Surface Pass** — Look at the target URL/parameter with fresh eyes.
   Send an inert marker, observe where it lands, classify the render context.
   Avoid querying MapStore or prior attempts until this concrete location/context exists.
3. **Fresh Observations** — Aim to identify 3-5 fresh parameters, sinks, render contexts,
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
| The plausible consumer of the input is a human or system the agent cannot observe - support/moderation/staff queues, grant or application review, log viewers, or a stored field with unaccountable render points | `blind-xss` | Callback collection, correlation, capture boundary, and Pending-OOB lifecycle for unobservable render points. |
| More than one is plausible | Load all relevant lanes, but keep notes separated by lane. |

Do not treat these lanes as mutually exclusive. A stored value can become DOM
XSS at render time; a reflected value can be inert in raw HTML but exploitable
after client-side parsing; a DOM route can also call server APIs.

## Incremental XSS Overlays

Load only the overlay that answers the next concrete question:

| Trigger | Load | Owns |
| --- | --- | --- |
| A controlled value persists, transforms, or may reach a later consumer | `xss-lifecycle` | Canary lineage, consumer expansion, and lane branching. |
| A warm/hot lane needs tailored payload choice, mutation, reduction, or creative exploration | `xss-payload-engineering` | Capability profile and directed/exploratory candidate queues. |
| Stack, renderer, sanitizer, parser, browser, or defense evidence could alter the next hypothesis | `xss-technology-research` | Bounded research packet and reusable-card promotion. |
| Filtering, normalization, challenge, or edge/origin differential is the current question | `waf-live-policy` | Defense-boundary characterization. |

The parent XSS agent owns synthesis, execution choices, and hypothesis closure.

## Shared Payload Sources

Use context-specific payloads, not generic spraying. Start with the shared
payload-selection reference:

- `skills/xss/references/payload-selection.md`

Useful local sources:

- `prompts/xss-playbook.md`
- `prompts/xss-payloads.md`
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
bbh agents/xss_framework.py \
  --target https://target.example/search?q=test \
  --program target \
  --mode full \
  --rate-limit 2
```

Use `agents/xss_hunter.py` for narrower parameter-focused passes.

```bash
bbh agents/xss_hunter.py \
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
4. Record framework/library, renderer/consumer, source, sink/trust boundary,
   transform/defense clues, and raw/browser differences; query concrete prior
   state without replacing current observation.
5. Load the matching incremental overlay when its trigger appears, then return
   its compact evidence packet to this lane.
6. Use the lane skill for browser proof, cleanup, and report shape.

## Pressure Mode

Every deliberate probe should resolve the canonical lane stream with
`resolve_attempts_path(...)` and append through `append_attempt(...)` to
`<lane>/attempts/_runs/<run-id>/attempts.jsonl`. Record the exact payload,
payload family, encoding, why that payload matched the context, observed
transform, browser result, block reason, and next mutation. Vulnerability class,
payload family, target, parameter, and input location are redacted event
metadata—not path taxonomy. Use `read_attempt_bucket(program, where=...,
limit=...)` for bounded cross-run discovery; use `read_attempts(exact_path, ...)`
only for exact-run forensic review.

Use this state model:

- `cold`: no reflection, storage, source-to-sink, sanitizer, or browser signal.
- `pending`: planted, correlated, awaiting an external callback channel
  (blind lane). `pending` is not `cold` and must not trigger the automatic
  pivot; move on to other hypotheses without retiring the lane.
- `warm`: marker reflects, persists, reaches DOM, hits a sanitizer, or changes
  browser/server output but execution is not proven.
- `hot`: attacker-controlled bytes influence a dangerous context, sanitizer
  decision, URL, script/JSON island, DOM sink, or stored render path.
- `exhausted`: representative families failed and the render/parser boundary
  is understood.

Only pivot automatically from `cold` or `exhausted`. A `pending` lane stays
open until its callback resolves or the run ends with the payload registered
as planted-and-pending. If the lane is `warm` or
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
6. load `xss-payload-engineering` for tailored mutation, novelty candidates, or
   signal reduction; load `xss-lifecycle` for later-consumer expansion
7. browser proof, residual next probe, later-consumer branch, or exact kill
   reason

Do not summarize the lane as "blocked" without saying which families were
tried, what blocked them, what evidence proves the block, and whether any
source/sink remains unexplored.

## Source Acquisition Over Sink Census

A sink you cannot feed is a fixture request, not a retired lane. Sink census
is cheap, repeatable, and stops converting on a mature target after the first
pass; the work that closes findings is obtaining an attacker-controlled
source that reaches a known sink. A completed census is a starting position,
and the next move from it is source acquisition - not a wider census. This is
not "stop doing sink analysis": the census is what surfaces the leads in the
first place.

### Classify the blocker before pivoting

When a sink is confirmed and no payload can reach it, the lane is blocked on
one of three things, and they route differently:

| Blocker | Route |
| --- | --- |
| The source exists but the agent lacks the artifact - an owned rich-text field, a second account, a dev-portal client, a published object, a session token from an interactive login | `account-testing-policy`. Create the fixture. This is testing work, not a dead end. |
| The source exists but its value space is server-constrained - allowlist, exact-match enum, format validation | `injection-testing-policy` / `waf-live-policy`. Characterize the constraint; a client-only regex is not a constraint. |
| No source reaches the sink at all - the value is CMS- or config-supplied with no user write path | Genuinely closed. Record it as a negative with the reason, so the next census does not resurface it. |

Only the third retires the lane. The first two are open work with a named
next action. Recording "sink confirmed, not exploitable" without saying which
of the three applies is what causes the same sink to be rediscovered by the
next census. This is **not** `exhausted` under the Pressure Mode definition
and must not be recorded as such - a blocked-on-fixture lane carries its
missing artifact as the reopening condition, consistent with the
blocker-first deepening location card (see `docs/xss-blocker-deepening`
promotion; reference resolves once that branch lands on beta).

### Name the missing artifact explicitly

When the blocker is the first row, the lead should state the artifact in one
line - "needs an owned rich-text field", "needs a csrfToken from an
interactive login on a 2FA account". A lead that names its missing fixture
can be picked up and closed by a later agent in one session. A lead that says
"blocked on exploitability" cannot.

### Rank by reachability and CSP, not by sink count

Sink count is the weakest of the available axes. Better ordering, cheapest
signal first:

1. **Source reachability** - is there any field, parameter, header or stored
   object an unprivileged attacker can write that reaches this bundle?
2. **CSP posture** - no CSP, or `script-src 'unsafe-inline'`, turns a
   marginal breakout into execution. A strict nonce-based policy demotes a
   sink that would otherwise rank first.
3. **Consumer diversity** - how many distinct renderers read the value. Raw
   storage with correct escaping in the primary renderer is a real lead if an
   email, export, OG tag or share page also reads it.
4. **Sink count** - last, and mostly useful as a tiebreak.

### Absent sanitizer is a weak signal; misconfigured sanitizer is the likelier find

Name-based sanitizer detection is unreliable against minified bundles and
produces both error directions. Useful minified tells include `[SafeHtml]`,
`allowedTags`, `allowedAttributes`, `allowedSchemes`, `ADD_ATTR`,
`RETURN_DOM`. Against a mature target, prefer reading the sanitizer's
**configuration** over searching for bundles that lack one: permitted tags
and attributes, allowed URL schemes, whether `target`/`href` survive, version
against known mXSS bypasses, and namespace handling for `<svg>` / `<math>` /
`<template>`. "No sanitizer present" is weak evidence in both directions -
server-side sanitization never appears in a client bundle at all. Bypass
payload families remain owned by `xss-payload-engineering`.

### Check for an amplifier before demoting a low-tier host

Program severity tiers and host importance are not the same as exploit
value. Before deprioritizing a sink on a low-tier or carve-out host, query
the ledger for a confirmed primitive on the same origin family that changes
what an XSS there is worth. A confirmed credentialed-CORS read across an
apex means an XSS on *any* subdomain - including a forum or help host
normally worth little - becomes the missing half of an account takeover. The
sink is unchanged; its value is not. This check costs one ledger query and is
a severity-reranking input to `impact-fit-policy`, not a substitute for it.

### Census stop condition

A sink census is a ranking instrument with a short half-life. Re-run it when
the corpus materially changes - new hosts pulled, bundles redeployed - not as
a default opening move. Re-running it over an unchanged corpus to produce a
fresh ranked list is motion, not progress, and the ranked list is not a
deliverable. This is consistent with the coverage decisions owned by
`class-derivation-policy`.

## Deep Default For Hybrid And Hunter Loop

For `/hybrid`, `/hunter-loop`, URL-batch, or route-cluster runs, XSS workers must
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
5. Track every deliberate probe in the resolved canonical Attempts stream with
   payload family, source, sink/context, encoding/normalization result, browser
   result, and stop reason. If no execution occurs, record the exact boundary.

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
- `Pending-OOB`: a correlated blind payload is planted and awaiting an
  external callback (blind lane). Between `Potential` and `Confirmed`. On
  fire, the lane becomes `Confirmed` - a callback from a privileged view is
  browser-executed by definition.
- `False positive`: the value is inert, safely encoded, unreachable, or blocked
  in the tested context.
