---
name: pwnfox
description: "Use when inspecting proxy traffic from PwnFox-profiled browser sessions, filtering Caido/Burp/proxy history by X-PwnFox-Color, or interpreting user phrases like 'Red session' as a distinct browser/auth/profile lane."
---

# PwnFox Profile Headers

Use this when a request/proxy task mentions PwnFox, colored sessions, browser
profiles, tab sessions, or a user phrase such as "look at the Red session".

PwnFox adds a request header that identifies the browser profile color:

```text
X-PwnFox-Color: <color>
```

Example:

```text
X-PwnFox-Color: red
```

Treat each PwnFox color as a distinct browser/profile lane. In practice, that
often means a distinct auth session, cookie jar, tab context, role, test
account, or workflow run.

## Phrase Mapping

When Ryushe says:

- "Red session" -> filter requests where `X-PwnFox-Color: red`
- "Blue session" -> filter requests where `X-PwnFox-Color: blue`
- "Green session" -> filter requests where `X-PwnFox-Color: green`
- "the red tab/profile/lane" -> use the same `X-PwnFox-Color: red` filter

Color matching should be case-insensitive in natural-language interpretation,
but preserve the observed header value when recording evidence.

## Workflow

1. Load `caido`, `intercepted-proxy`, `single-request-grabber`, or the relevant
   proxy/request skill first.
2. If Ryushe names a color, filter request history by the matching
   `X-PwnFox-Color` header.
3. If multiple colors appear, keep them separated as distinct session lanes.
4. Label findings, comparisons, and request notes with the PwnFox color.
5. When comparing auth behavior, compare equivalent requests across colors
   only after confirming the account/resource ownership for each lane.

## Request Filtering

Use the header as the primary session discriminator:

```text
Header name:  X-PwnFox-Color
Header value: <requested color>
```

For proxy history review, search or filter for the exact header name first,
then narrow by color value. If the header is absent, say that the observed
traffic is not PwnFox-labeled instead of guessing which profile produced it.

## Guardrails

- Do not assume two colors are the same account just because the URLs match.
- Do not merge evidence from different colors unless the comparison is explicit.
- Do not copy cookies, bearer tokens, CSRF tokens, or private request bodies
  between colors unless Ryushe explicitly approves that session-transfer test.
- Keep raw secrets out of chat, prompts, logs, reports, and commits.

## Evidence

Record:

- requested color and observed `X-PwnFox-Color` value
- full URL, method, status, and auth state
- proxy source, such as Caido/Burp/browser history
- account/resource alias for that color when known
- whether the header was present, absent, or inconsistent
- comparison color if doing cross-session auth testing

