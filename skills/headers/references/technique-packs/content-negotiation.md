# Content Negotiation Headers

Use when response format, body parser, schema validation, or API version behavior changes with representation headers.

## Checks

- Compare `Content-Type` values for the same body.
- Compare `Accept` values for the same endpoint.
- Check charset, boundary, compression, and API version headers only when the stack advertises support.
- Watch for validation bypasses, deserialization differences, hidden fields, or alternate error bodies.

## Mutations

- `Content-Type: application/json`
- `Content-Type: application/x-www-form-urlencoded`
- `Content-Type: text/plain`
- `Content-Type: application/json; charset=utf-8`
- `Accept: application/json`
- `Accept: text/html`
- `X-API-Version: 1`
- `X-Requested-With: XMLHttpRequest`

## Evidence Required

- Same semantic request under different representation headers.
- Parser or validation delta.
- Security impact, not only a different error serializer.

## Stop

Stop before sending malformed high-volume payloads or parser stress tests without approval.
