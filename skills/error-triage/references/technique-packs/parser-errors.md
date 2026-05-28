# Parser Errors

Use for `400`, `415`, schema validation, JSON/XML/body parser errors, content-type mismatch, and malformed parameter responses.

## Checks

- Compare same semantic request across `Content-Type` and `Accept` values.
- Identify which parameter or body segment caused the error.
- Check duplicate keys, missing values, nulls, arrays, and type swaps only in a small bounded set.
- Route content/header behavior to `/headers` content-negotiation.

## Route

- content negotiation or parser choice -> `/headers`
- URL/encoding/path parser confusion -> `/bypass`
- schema mismatch with object/role impact -> `/access-control`
- injection-like parser behavior -> matching vuln skill

## Evidence Required

- Baseline valid request.
- Minimal invalid request.
- Parser or validation delta.
- Security relevance.

## Stop

Stop before parser stress, large payloads, entity expansion, archive bombs, or destructive malformed writes.
