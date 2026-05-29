# CSRF Token

Use when a live request includes a per-action or per-request CSRF token, one-time nonce, one-use challenge token, or browser-generated token that may go stale if replayed later.

## Checks

- Identify where the token came from: DOM, hidden input, meta tag, cookie, previous response, or same-origin token endpoint.
- Capture the token only from the owned browser/session flow.
- If the token appears only after multiple setup requests, forward setup requests until the target action request appears.
- Prefer live intercept/modify when replaying an old token is invalid.
- Test omission, stale token, or cross-session token only when the action is safe and owned.
- Do not try to generate or guess CSRF tokens. Use the legitimate owned flow and preserve the live token while changing only the approved test field.

## Allowed Modifications

- Remove token for a missing-token check.
- Replay same owned request once to test token freshness.
- Swap approved test-account context only when both sides are owned and the action is non-destructive or destructible-approved.
- Preserve the fresh token while changing one approved resource/account identifier for authorization testing.
- Change `Origin`/`Referer` only through `/headers` origin guidance.

## Evidence Required

- Token location, redacted.
- Owned session/account alias.
- Action endpoint and method.
- Before/after state for safe action.
- Whether token was enforced, bound, stale, or reusable.

## Stop

Stop if the token cannot be obtained through the owned flow, if the action is destructive without explicit approval, or if the test would involve non-owned accounts/resources.
