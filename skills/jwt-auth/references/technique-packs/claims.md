# Claims

Use when authorization depends on payload claims such as `iss`, `aud`, `jti`, `sub`, `role`, `scope`, `tenant`, `org_id`, `user_id`, `exp`, or `nbf`.

## Checks

- Compare low-role and allowed-role claim sets from owned accounts before mutating.
- Test role/scope/tenant/object claims only against owned resources.
- For `aud`, try removal, expected audience, wildcard only if hinted, and array form.
- For `iss`, try expected issuer values; for URL issuer behavior use only owned callbacks.
- For `jti`, try removed, null, duplicate, and one benign quote probe if evidence suggests database lookup.
- For replay/expiry, compare current, expired, future `nbf`, and logout/reuse behavior.

## Evidence Required

- Claim mutation changes authorization or object boundary.
- The affected claim is tied to role, scope, tenant, object, issuer, audience, or token lifecycle.
- Response proves protected behavior, not just status drift.

## Stop

Stop on non-owned objects, real-user data, internal SSRF targets, or live SQL extraction. Route issuer URL fetching to `/ssrf`.
