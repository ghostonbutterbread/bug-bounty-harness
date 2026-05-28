# Access Errors

Use for `401`, `403`, authorization failures, ownership denials, and resource-bound access errors.

## Checks

- Identify whether the resource is owned, approved test-account owned, server/API-owned, or unknown.
- Compare logged-out, intended user, and approved alternate user if available.
- Check whether the response body leaks private data despite denial.
- For concrete owned `403`, route to `/403`.

## Route

- `403` on owned/server/API endpoint -> `/403`
- object ownership boundary -> `/idor`
- role/tenant/workflow/auth-state boundary -> `/access-control`
- trusted-header/path/method behavior -> `/headers` or `/bypass`

## Evidence Required

- Full URL and resource ownership.
- Auth state and account aliases.
- Denial baseline and any safe comparison response.
- Reason the next test is allowed.

## Stop

Stop if the resource belongs to a real user or organization outside approved accounts.
