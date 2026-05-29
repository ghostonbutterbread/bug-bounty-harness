# Unhandled Errors

Use for custom application errors, mixed signals, unknown status codes, nonstandard JSON error envelopes, or cases where the status code and body point to different meanings.

## Checks

- Preserve the current task goal before interpreting the error.
- Identify whether the error blocks the task, confirms expected behavior, or creates a new safe lead.
- Compare against one known-good baseline if available.
- Check whether the response looks like auth, routing, parser, rate-limit, or business-logic behavior even if the status code is unusual.
- Prefer one bounded next move instead of trying every related skill.

## Route

- missing live token, generated header, or one-shot body shape -> `/single-request-grabber`
- route existence uncertainty -> `/live-map` or `/fuzz`
- header/content negotiation suspicion -> `/headers`
- auth, role, tenant, or object boundary suspicion -> `/access-control` or `/idor`
- generic bypass family with a concrete hypothesis -> `/bypass`
- anti-abuse, CAPTCHA, WAF, or unexplained blocking -> `/waf` or stop

## Evidence Required

- Full URL, method, status, body length, and visible error text.
- Current task goal and why the error matters to that goal.
- Ownership and destructible-resource decision.
- Why the selected next move is bounded and safe.
- What ambiguity remains after the decision.

## Stop

Stop when ownership is unclear, the next step would touch non-owned data, the operation is destructive, the behavior looks like anti-abuse enforcement, or the only available next tests would be broad guessing.
