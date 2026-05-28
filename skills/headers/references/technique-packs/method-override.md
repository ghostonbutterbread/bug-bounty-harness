# Method Override Headers

Use when HTTP method handling may bypass routing or authorization checks.

## Checks

- Compare allowed and rejected methods on the same route.
- Test override headers only after baseline method behavior is known.
- Prefer read-only methods first: `GET`, `HEAD`, `OPTIONS`.
- Treat unsafe methods as approval-gated unless the target resource is marked `destructible: yes`.

## Mutations

- `X-HTTP-Method-Override: GET`
- `X-HTTP-Method-Override: POST`
- `X-Method-Override: PATCH`
- `X-HTTP-Method: DELETE`
- body parameter `_method=PUT`
- query parameter `_method=DELETE`

## Evidence Required

- Original method/status.
- Override method/status.
- Whether authorization, validation, or route handling changed.

## Stop

Stop before unsafe writes, deletes, purchases, invites, password changes, or workflow transitions unless explicitly approved and isolated.
