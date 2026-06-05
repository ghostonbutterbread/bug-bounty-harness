---
name: reflected-xss
description: Use when attacker-controlled input appears in the immediate HTTP response or browser-rendered page and needs reflected XSS context classification, payload selection, mutation, and browser verification.
---

# Reflected XSS

Use this lane when a marker reflects immediately in the response or rendered
page.

The goal is to identify the exact output context, break that context with the
smallest useful payload, then mutate as needed until execution is proven or a
real boundary appears.

## Load First

- `xss`
- `live-testing-policy`
- `waf-live-policy` if filters, bot defenses, WAF, sanitizers, or parser quirks
  shape the test
- `skills/xss/references/payload-selection.md`

## Inputs To Test

Check more than query parameters when evidence supports it:

- query values and parameter names
- path segments and slugs
- form body fields
- JSON keys and values
- headers: `Referer`, `User-Agent`, `X-Forwarded-*`, custom app headers
- cookies reflected into templates/bootstrap data
- redirect targets and URL-bearing params

## Context Checklist

Record where the marker lands:

- HTML text/body
- quoted attribute
- unquoted attribute
- URL-bearing attribute
- inline JavaScript string
- JSON/bootstrap blob
- template literal
- CSS/style
- escaped server response that client-side JS later decodes

Do not choose payloads before context classification.

## Testing Loop

1. Send a marker with a unique token.
2. Compare raw HTTP and browser-rendered behavior when possible.
3. Select a payload family matching the exact context.
4. If blocked or encoded, mutate within the same family first.
5. Move across families only when the response shows a parser or sanitizer
   difference worth exploring.
6. Use browser verification or target-owned checker for confirmation.

## Good Payload Thinking

Prefer reasoning like:

- "I am inside a quoted attribute, so I need quote breakout plus a trigger."
- "The server encodes `<` but leaves quotes, so attribute injection may still
  work."
- "The raw response is escaped, but the frontend assigns it into `innerHTML`."
- "The WAF sees one decoding layer; the browser/backend may see another."
- "The query is encoded but the fragment remains raw in `location.toString()`."

Use Ryushe's payload examples for shapes, but adapt them to the context.

## Browser Proof

Confirmed reflected XSS needs execution proof:

- alert or equivalent target checker signal
- console side effect under controlled browser
- DOM mutation proving script execution
- target-owned lab checker success

If browser tooling is unavailable, mark as `Likely` or `Potential` and record
the blocked proof step.

## Stop Conditions

- input is fully encoded in the tested browser context
- no signal after representative context-specific mutations
- WAF/rate pressure requires cooldown
- next step would involve non-owned data, real users, staff-visible workflows,
  or out-of-scope redirects

## Report

Include full URL, parameter/header/body field, reflected context, payload,
mutation family, browser proof status, and stop reason.
