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
