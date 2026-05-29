# CSRF Token

Use when a live request includes a per-action or per-request CSRF token.

## Checks

- Identify where the token came from: DOM, hidden input, meta tag, cookie, previous response, or same-origin token endpoint.
- Capture the token only from the owned browser/session flow.
- Prefer live intercept/modify when replaying an old token is invalid.
- Test omission, stale token, or cross-session token only when the action is safe and owned.

## Allowed Modifications

- Remove token for a missing-token check.
- Replay same owned request once to test token freshness.
- Swap approved test-account context only when both sides are owned and the action is non-destructive or destructible-approved.
- Change `Origin`/`Referer` only through `/headers` origin guidance.

## Evidence Required

- Token location, redacted.
- Owned session/account alias.
- Action endpoint and method.
- Before/after state for safe action.
- Whether token was enforced, bound, stale, or reusable.

## Stop

Stop if the token cannot be obtained through the owned flow, if the action is destructive without explicit approval, or if the test would involve non-owned accounts/resources.
