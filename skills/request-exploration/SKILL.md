---
name: request-exploration
description: "Systematic live request mutation: flip booleans, field ops, headers, content-type, parser differentials, replay vs intercept, null/empty testing. Inherits live-testing-policy scope/rate/ownership rules."
---

# Request Exploration

Use when testing a known live request or mapped workflow and you want to systematically mutate it to discover behavior, edge cases, and security boundaries.

This is a thinking loop, not a request-count cap. Continue while each mutation family produces new signal. Stop or pivot when responses become redundant, rate limits appear, or a stronger lead emerges.

## Load Order

1. Read scope, owned-account context, and `/live-testing-policy`.
2. Confirm every account and resource is owned or explicitly approved.
3. Identify whether the endpoint uses a one-time token, CSRF token, payment session, state transition, or any stateful workflow. If yes, use live interception (proxy/Burp) instead of replay to avoid token reuse false negatives.
4. Capture the baseline request: method, URL, headers, body, and the expected normal response.
5. Route focused lanes:
   - header-specific mutations → `/headers`
   - WAF/filter behavior → `/waf-live-policy`
   - structured focused exploration → `/hypothesis-live-testing`
6. For training, calibration, or examples, read `references/juice-shop-lab.md` and `references/local-notes-map.md`.

## Workflow

Test one mutation family at a time and observe whether the response changes in ways that matter — status, body length, validation errors, behavior side effects, entitlement differences, or data exposure.

For each mutation family, document: what changed, what the baseline response was, what the mutated response was, and whether it represents a security-relevant difference.

The examples below are **patterns to think with**, not a fixed checklist. Adapt them to the target's actual request shape, parser, auth state, and ownership model. If a request shape or response behavior suggests a mutation not listed here, try it.

### 1. Boolean flip
Change `true`/`false`, `0`/`1`, `yes`/`no`, `enabled`/`disabled`, `active`/`inactive`, `premium`/`basic`, `staff`/`customer`, `internal`/`external`, `isAdmin`, `isModerator`, `isOwner`, `hasAccess`, `verified`, `approved`, `paid`, `subscribed`.

Examples:
- Payment request has `payment_option: false`. Change to `true` and observe whether the price drops, a premium feature unlocks, or an entitlement flips without payment.
- Registration sets `role: "user"`. Try `role: "admin"` or `"moderator"` and check downstream privilege gating.
- Response includes `"subscribed": false`. Re-send the mutation request with `"subscribed": true` and see if the server trusts a client-side flag.
- API response includes `isOwner` or `canEdit`. Reflect the same key back in the next state-changing request and see if the server trusts it.

### 2. Integer and type injection
Try `1`, `-1`, `0`, `99`, `999999`, `null`, `true`, `false`, empty string, or an array where a scalar is expected.
Look for: type coercion, negative-price billing, range bypass, integer overflow, MAX_INT, or privilege escalation through number-shaped fields.

Examples:
- Quantity field in a cart API. Try `-1` and check whether the total becomes negative or the item is added at no cost.
- Price or discount field. Try `0`, `-100`, `0.01`, or a string like `"free"`.
- User ID or role ID. Try `0` (often reserved for admin/superuser in some frameworks), `-1`, or a very large integer.
- Boolean-shaped field. Try `2`, `99`, `-1`, `"true"`, or `[true]` to see whether the parser coerces or rejects non-standard values.

### 3. Field duplication and removal
Duplicate a field with the same or different value. Remove a field entirely. Change field order in JSON. Send extra fields not in the original request.

Examples:
- HTTP Parameter Pollution: send `?role=user&role=admin` and observe which value the server or backend framework picks.
- JSON body with duplicate keys: `{"BasketId":"<owned_a>","ProductId":1,"BasketId":"<owned_b>"}` — last-value-wins frameworks may pick the second one, bypassing access checks keyed on the first.
- Mass assignment: add `isAdmin`, `role`, `companyId`, `plan`, `credit`, or `verified` to a registration or profile update where the field is not normally present.
- Remove a required-looking field entirely and observe whether the server defaults, rejects, or silently ignores the absence.

### 4. Header changes
Remove auth-related headers (Authorization, Cookie, X-API-Key). Swap Content-Type. Add/remove Origin, Referer, X-Forwarded-For, X-Real-IP, X-Forwarded-Host, X-Forwarded-Proto, X-Original-URL, X-Rewrite-URL. Load `/headers` skill for deeper header poisoning guidance.

Examples:
- Remove the Authorization header from a state-changing request and check whether the server still processes it.
- Add `X-Forwarded-For: 127.0.0.1` or `X-Real-IP: 127.0.0.1` to a rate-limited endpoint and observe whether rate limiting or IP-based access controls are bypassed.
- Change `Content-Type: application/json` to `text/xml` or `application/x-www-form-urlencoded` with the same payload and observe parser behavior differences.

### 5. Content type and JSON shape differentials
Send JSON as form-encoded, form as JSON, XML where JSON is expected, multipart where form is expected. Change Accept header. Probe whether the server and backend parse the body differently based on Content-Type.

Examples:
- GraphQL endpoint normally expects `application/json`. Try `x-www-form-urlencoded` or `multipart/form-data` with the same mutation payload.
- REST endpoint that accepts JSON. Try sending the same payload as URL-encoded form data and compare whether validation or access-control behavior differs.
- Add or change the Accept header to `application/xml`, `text/html`, or `*/*` and observe whether the response format reveals internal error messages or different parser paths.

### 6. Parser differential testing
Same payload, different encoding: URL-encode, double URL-encode, Unicode escape, hex, base64. Different quoting: single vs double, no quotes. Nested JSON vs flat. Array vs scalar for single-value fields.

Examples:
- Send `{"id": 1}` vs `{"id": [1]}` vs `{"id": {"$gt": ""}}` and observe whether a NoSQL or ORM parser treats the shape differently.
- Send `role=admin` vs `role=%61dmin` vs `role=%25%36%31dmin` and test whether a WAF, filter, or backend parser normalizes inconsistently.
- Send `{"user":"attacker"}` vs `{"user":["attacker","victim"]}` and observe whether a multi-value array bypasses single-value access checks.

### 7. Missing, null, and empty values
Remove fields one at a time. Send `null` vs `""` vs `[]` vs `{}` vs omitted entirely.

Examples:
- Registration requires `email`, `password`, `name`. Remove `email` and see whether the server accepts a user with no email, defaults to null, or rejects.
- Password-change endpoint expects `oldPassword`, `newPassword`. Remove `oldPassword` and check whether the server skips current-password verification.
- Send `{"id": null}` to an endpoint that normally requires an ID and observe whether it returns all records, the first record, or an error.
- Send `{"role": ""}` instead of omitting it entirely and compare behavior to `{"role": null}`.

### 8. Replay vs live-intercept comparison
For stateful endpoints, send the exact captured request (replay) and compare the response to a live-intercepted mutation of the same request.

Examples:
- Payment flow: capture a checkout request with a one-time token. Replay it unchanged and observe an "already processed" or "token expired" error. Then intercept the same request live and mutate the amount before the token is consumed. If replay fails but intercept succeeds, the endpoint is replay-safe but still vulnerable to intercept-time mutation.
- Password reset: capture the final password-change request. Replay it and observe whether the reset token is single-use. Then intercept the reset flow live and mutate the target account ID before the token is redeemed.
- CSRF-protected endpoint: replay the exact request and observe whether the CSRF token blocks replay. Then intercept live and mutate the body before the CSRF token is paired with it.
- If replay and live-intercept both produce the same result, the endpoint is replay-safe and the mutation is the cause of any behavioral change. If only live-intercept produces a different result, the token or state transition is the gate.

## Stop Conditions

Stop on: out-of-scope URL, non-owned resource without clear public access, human-facing action, destructive mutation, paid transaction authorization, program-disallowed behavior, instability, or sensitive-data exposure beyond minimal classification proof.

## Evidence

Record full URLs, request method, auth state, owned account aliases, mutation class, baseline vs mutated response deltas, and whether the delta is security-relevant. Never record raw passwords, cookies, bearer tokens, reset links, reset tokens, or private data.
