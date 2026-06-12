---
name: dom-xss
description: Use when XSS depends on browser-side sources and sinks such as URL/query/hash, router state, local/session storage, cookies, postMessage, DOM parsing, framework render paths, or client-side sanitizer behavior.
---

# DOM XSS

Use this lane when the server response alone is not the whole story. DOM XSS
requires browser-side source-to-sink reasoning and execution proof.

## Load First

- `xss`
- `live-testing-policy`
- `waf-live-policy` for browser/raw-client, sanitizer, and parser differences
- `chromium-test` when local browser verification is possible
- `skills/xss/references/payload-selection.md`

## Source Map

Look for attacker-controlled sources:

- `location`, `location.href`, `location.search`, `location.hash`
- `document.URL`, `document.referrer`
- router params and SPA state
- `localStorage`, `sessionStorage`
- cookies
- `postMessage` event data
- `BroadcastChannel`, `MessageChannel`
- URLSearchParams and custom query parsers
- API responses later rendered by the frontend

## Sink Map

High-signal sinks:

- `innerHTML`, `outerHTML`
- `insertAdjacentHTML`
- `document.write`, `document.writeln`
- `eval`, `Function`, string timers
- `setAttribute` on URL/event-sensitive attributes
- `srcdoc`
- dynamic script creation
- framework raw HTML helpers
- sanitizer trust-bypass helpers

Framework-specific review:

- React: `dangerouslySetInnerHTML`, raw markdown/HTML renderers, unsafe URL
  props, hydration mismatch paths
- Vue: `v-html`, dynamic template compilation, custom components forwarding raw
  HTML
- Angular: `[innerHTML]`, `bypassSecurityTrustHtml`,
  `bypassSecurityTrustUrl`, `bypassSecurityTrustScript`

## Testing Loop

1. Identify the source and sink.
2. Confirm the source controls bytes reaching the sink.
3. Determine whether the browser decodes, normalizes, strips, or preserves
   payload bytes.
4. Build payloads for the browser parser context, not just the HTTP response.
5. Verify execution in a browser or target-owned checker.
6. If browser tooling is unavailable, save enough source/sink evidence for the
   next browser-capable agent and mark as `Likely` or `Potential`.

## Deep-Run Requirements

For `/hybrid`, `/deep-hunt`, URL-batch, or route-cluster handoffs, do not stop
at "marker reflected" or "framework detected." Produce a compact source-to-sink
map:

- source inventory: query, hash, router state, storage, `postMessage`,
  bootstrap data, API response, and framework state candidates
- sink inventory: DOM insertion APIs, raw HTML helpers, URL attributes,
  iframe/srcdoc/embed strings, JSON/XML data islands, and sanitizer trust
  boundaries
- framework evidence: React/Vue/Angular/router/state-library clues, bundle
  names, CSP, and browser-vs-raw response differences
- payload accounting: one `attempts.jsonl` row per deliberate source/sink probe
  with payload family, transformation result, browser result, and stop reason

If the route is browser-only due to challenge or client rendering, raw HTTP is
not sufficient evidence to close the DOM lane.

## DOM-Specific Payload Thinking

DOM payloads often succeed because two components disagree:

- server encodes query, but fragment remains raw in `location.toString()`
- hidden input stores encoded HTML, but `.value` decodes before `innerHTML`
- sanitizer runs before later string concatenation
- router decodes once and component decodes again
- client blocks characters but server/checker accepts a direct signed URL
- browser parser recovers malformed markup differently than expected

For hard labs and real apps, mutation is normal. Try fragments, duplicate
params, encoded delimiters, parser recovery, alternate source locations,
storage writes, message bodies, route state, and browser-only behavior when
they are scoped and rate-limited.

## Browser Verification

Prefer:

- `chromium-test` launcher
- Playwright when already installed or safely installable in a local temp
  workspace
- target-owned checker endpoint when the lab/application provides one

Record if browser verification is blocked by missing Chromium, missing
Playwright, CAPTCHA, challenge, rate pressure, or scope.

## postMessage Checks

For `postMessage`:

- confirm allowed origins and target windows
- send messages only to scoped pages
- avoid secrets in message bodies
- test object shape confusion, nested fields, and prototype-sensitive parsing
- verify the sink after message handling

## Report

Include:

- source
- sink
- transformation chain
- payload source location: query, hash, storage, message, API response
- browser/tool used
- execution proof or exact verification blocker
- framework/sanitizer behavior
- stop reason
