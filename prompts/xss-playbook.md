# XSS Testing Playbook

## Overview

Use this as a decision tree: probe the input, classify the reflection or sink context, choose the matching testing lane, verify execution, then report with enough detail for reproduction and cleanup.

See `prompts/xss-payloads.md` for the payload catalog, WAF bypasses, and framework-specific notes.

## Decision Tree

1. Probe the input.
2. If it reflects immediately, classify the context and go down the reflected lane.
3. If it persists and renders later, go down the stored lane.
4. If it only reaches a client-side source or sink, go down the DOM lane and keep it `Potential` until browser-verified.
5. Verify the result with the lowest-noise payload that matches the context.
6. Report the finding with context, sink, bypass, confirmation status, interaction, and cleanup notes.

## Deep-Run Default

For hybrid, deep-hunt, URL-list, and route-cluster work, the default is deeper
source-to-sink analysis, not broad payload spraying. A worker should be able to
answer:

- Which attacker-controlled source was used?
- Which sink or render context received the bytes?
- Which framework, router, sanitizer, WAF, or browser/raw-client difference
  shaped the result?
- Which payload families were tried, and why those families matched the
  observed context?
- How many deliberate probes were made, and what stopped the lane?

Minimum artifact expectation for these runs:

- `attempts.jsonl`: one record per deliberate observation or payload probe.
- `summary.md`: route family, source map, sink map, framework clues, payload
  family results, confirmed/potential/false-positive decision, and next handoff.
- `handoff.json`: required when the next step belongs to another lane, browser
  profile, authenticated account, or source-review worker.

If a worker cannot write these artifacts, the XSS lane is incomplete even when
the raw log contains useful observations.

## Pressure Mode

Use pressure mode when the vector has signal but no execution yet. Signal
includes reflection, storage, DOM reachability, sanitizer interaction,
browser/server render differences, unusual encoding, WAF-specific blocking, or
partial control of a dangerous sink.

State model:

- `cold`: no signal yet; use small canaries to decide whether this vector exists.
- `warm`: signal exists but no exploit; classify context and defenses.
- `hot`: partial control or bypass clue; keep deliberate mutation pressure.
- `exhausted`: representative families failed and the block is understood.

The worker may pivot automatically from `cold` or `exhausted`. For `warm` or
`hot`, continue on the same vector unless policy, ownership, rate, browser
access, or cleanup safety blocks the next probe.

Each attempts row should include:

- hypothesis and boundary being tested
- exact payload or canary
- payload family
- encoding or placement
- why this payload was selected
- observed transform
- evidence path or response/browser summary
- block reason
- next mutation or kill condition
- pressure state

Do not report only "payload blocked." Report what transformed it, which
families were tried, and what remains worth testing.

## Tool-Assisted Discovery

Use tool output as an input map for the XSS lane, not as final proof.

For install checks, command shapes, output paths, and hybrid handoff packet
format, read:

- `/home/ryushe/projects/bug_bounty_harness/skills/bounty-tools/SKILL.md`
- `/home/ryushe/projects/bug_bounty_harness/skills/xss/references/tool-assisted-discovery.md`

Dalfox is preferred for parameter mining and reflection triage across known URL
sets. Use it to discover hidden parameters, identify reflected inputs, collect
injectable/free character behavior, and capture WAF clues before deciding which
payload families or bypasses fit.

Dursgo is preferred for application mapping and browser-aware discovery. Use it
to crawl route clusters, find forms and endpoints, run JavaScript-rendered SPA
mapping, and produce `xss-reflected`, `xss-stored`, or `domxss` leads for
follow-up.

Every Dalfox or Dursgo lead still needs normal lane handling:

- classify the source, sink, and render context
- route to reflected, stored, or DOM XSS
- verify browser execution before marking `Confirmed`
- write tool name, command/config, output path, and stop reason into the lane
  artifacts

## 1. Probe

Start by finding every place attacker-controlled data can enter the application.

### Coverage Checklist

- Query parameters
- Form fields and other `POST` bodies
- JSON keys and values in API requests
- Headers such as `User-Agent`, `Referer`, `X-Forwarded-*`, and custom app headers
- Cookies that are reflected into HTML, JS, or templates
- Path segments, slugs, filenames, and router params

### Probe Method

1. Send a low-noise marker such as `xsstest123` or a UUID.
2. Check whether the value is reflected, stored, or reaches client-side code.
3. Record where it appears:
   - Raw HTML body
   - Attribute value
   - Inline script or JSON blob
   - URL-bearing attribute such as `href` or `src`
   - CSS or style block
   - Template literal or frontend render path
4. Note filtering behavior early:
   - Encoded
   - Stripped
   - Truncated
   - Blocked by WAF

### Source-To-Sink Inventory

Before selecting payloads in a deep run, map likely sources and sinks.

Sources:

- `location.search`, `location.hash`, `location.href`, `document.URL`
- `URLSearchParams`, client router params, route state, and path params
- form fields, API responses, bootstrap data, JSON data islands
- local/session storage, cookies, `postMessage`, message channels

Sinks:

- HTML text, quoted/unquoted attributes, URL-bearing attributes
- input values and framework-controlled form state
- inline scripts, JSON/bootstrap blobs, template literals, XML/iframe strings
- `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `srcdoc`, dynamic scripts
- React `dangerouslySetInnerHTML`, markdown/raw HTML renderers, unsafe URL
  props, hydration/state handoff paths
- Vue `v-html`, Angular `[innerHTML]` or `bypassSecurityTrust*`, sanitizer
  trust-bypass helpers

Record enough framework evidence to make payload selection defensible: bundle
names, router/framework hints, CSP, sanitizer behavior, WAF/challenge signal,
and raw HTTP vs browser-rendered differences.

## 2. Classify Context

Do not pick payloads before classifying the context. Reflection quality matters more than payload volume.

| Context | What To Confirm | Typical Next Step |
|---------|-----------------|-------------------|
| HTML body | Marker lands between tags | Try tag-breaking or event-handler HTML payloads |
| Quoted attribute | Marker lands inside `'...'` or `"..."` | Break out of the quote, then add an event or tag |
| Unquoted attribute | Marker lands in an unquoted attribute value | Use whitespace, `/`, `>`, or event handlers |
| JS string | Marker lands inside `'...'` or `"..."` in script | Escape the string and terminate safely |
| Template literal | Marker lands inside `` `...` `` | Break with `` `${...}` `` or close the literal if possible |
| URL / `href` / `src` | Marker controls a navigated or rendered URL | Test `javascript:`/`data:` handling and navigation constraints |
| CSS | Marker lands in inline style or stylesheet | Focus on CSS-based execution pivots or data exfil style impacts |
| DOM source-to-sink | Attacker input flows to a dangerous sink in JS | Treat as potential until a browser proves execution |

If you only have a source-to-sink chain such as `location.hash -> innerHTML`, it is a potential DOM issue until browser verification confirms code execution.

### Context-Specific Escalations

- For DOM URL sources, compare `location.search`, `location.hash`,
  `document.URL`, and `location.toString()`. A fragment can preserve quote or
  attribute-breakout characters that would be encoded or normalized in the
  query string.
- For template literals, if `${...}` survives but parentheses or backticks are
  stripped, test expression-only execution paths such as assigning
  `location='javascript:alert%28document.cookie%29'`.
- For URL-bearing attributes, if obvious `javascript:` is stripped, test
  browser-normalized scheme variants such as tab or carriage-return inserted
  inside the scheme before abandoning the URL-navigation lane.
- For JavaScript strings under selectable legacy charsets, browser-test
  stateful charset switches such as ISO-2022-JP `ESC ( J` before quote
  breakouts. Server-added backslashes may decode as a yen sign and stop
  escaping the quote.

## 3. Choose Lane

Pick the lane that matches how the input behaves.

### Reflected Lane

Use when the marker appears in the immediate response.

1. Confirm the reflection is attacker-controlled and not just echoed in a safe text node.
2. Select payloads for the exact context.
3. Re-test through alternate inputs, not just query params:
   - `POST`
   - JSON
   - headers
   - cookies
   - path segments
4. If filtering or WAF blocking occurs, move to the bypass catalog in `prompts/xss-payloads.md`.

### Stored Lane

Use when the input persists and later renders.

1. Find the storage point and the render point.
2. Verify whether the payload is visible to the same user, other users, or admins.
3. Record any required interaction:
   - opening a page
   - expanding a widget
   - hovering or clicking
   - moderation or admin review
4. Plan cleanup before testing anything that persists.

### DOM Lane

Use when the browser assembles the sink after page load.

1. Map the source:
   - `location`
   - `document.URL`
   - `document.cookie`
   - `postMessage`
   - storage APIs
   - client-side router params
2. Map the sink:
   - `innerHTML`
   - `outerHTML`
   - `insertAdjacentHTML`
   - `document.write`
   - `eval`
   - `Function`
   - framework render helpers
3. Treat source-to-sink evidence as potential until browser verification proves execution.

## 4. Verify

Verification should be context-aware and low-noise.

### Verification Standard

1. Reproduce with the minimum payload needed for the classified context.
2. Confirm whether execution is immediate, delayed, or interaction-based.
3. For DOM findings, verify in a browser. Static source review alone is not enough for confirmation.
4. For stored findings, revisit the render location and confirm persistence.
5. Capture evidence:
   - request used
   - rendered context
   - sink
   - browser result
   - any WAF/filter bypass required

### Payload Accounting

For route-cluster and hybrid workers, count payloads by family rather than only
by raw request count. Typical families:

- marker/baseline
- attribute breakout
- tag breakout
- event-handler
- URL-scheme/navigation
- template literal/expression
- JSON/XML/iframe attribute
- hash/router/source
- storage/message source
- WAF/parser mutation

Stop increasing volume when representative probes prove the context inert.
Escalate by changing the source/sink hypothesis, not by spraying unrelated
polyglots.

If the context is `warm` or `hot`, representative probes should cover the
family that matches the observed boundary before moving away. For example, do
not leave an attribute-context reflection after only a script-tag payload; test
the quote/whitespace/event-handler boundary and record the exact encoding or
sanitizer reason that stopped it.

### Status Rules

- `Confirmed`: execution occurred or the browser verified the sink path.
- `Potential`: reflection or source-to-sink exists, but execution is not yet proven.
- `False Positive`: reflection is inert, server-side escaped, or sink is unreachable in practice.

## 5. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/xss/findings.md`

Include:

- XSS type: reflected, stored, or DOM
- Exact input vector: query, `POST`, JSON, header, cookie, or path segment
- Reflection context
- Sink or render path
- Payload used
- Bypass used, if any
- Confirmation status
- Browser verification status
- Required interaction
- Cleanup needed for stored payloads

## Advanced Bypasses

Use these only after a normal context-specific payload shows promising reflection or a reachable sink. Polyglots and other low-signal payloads come last because they are noisy and harder to reason about.

### When To Escalate

- Reflection is promising but heavily filtered
- A WAF blocks only obvious tokens
- The application normalizes case, quotes, or separators
- You need a framework-specific sink bypass

### What To Use

- Encoding and double-encoding
- Case mutation
- Event-handler swaps
- Tag and attribute minimization
- Alternate separators and control characters
- Polyglots only after the context is already understood
