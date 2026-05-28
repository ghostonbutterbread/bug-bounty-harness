# Method Errors

Use for `405`, method not allowed, method-specific `403`, and inconsistent behavior across HTTP methods.

## Checks

- Compare `GET`, `HEAD`, and `OPTIONS` first.
- Record the `Allow` header if present.
- Check whether method override headers are supported through `/headers`.
- Do not try unsafe methods against non-destructible resources.

## Route

- header-based method override -> `/headers`
- method-specific authorization boundary -> `/access-control`
- route discovery from `Allow` or `OPTIONS` -> `/live-map` or `/fuzz`

## Evidence Required

- Method matrix with status/body length.
- Auth state and resource ownership.
- Whether the method difference affects security.

## Stop

Stop before unsafe `PUT`, `PATCH`, `DELETE`, purchase, invite, password, or workflow-transition requests unless approved and isolated.
