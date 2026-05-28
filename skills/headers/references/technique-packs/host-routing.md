# Host Routing Headers

Use when host headers influence upstream routing, tenant selection, absolute URL generation, reset links, webhooks, or cache keys.

## Checks

- Compare canonical `Host` to sibling subdomain or controlled host values.
- Check whether `X-Forwarded-Host` changes generated links, redirects, tenant context, or upstream service.
- Compare cache headers and vary behavior.
- Keep proofs non-destructive and owned-account scoped.

## Mutations

- `Host: <alternate-in-scope-host>`
- `X-Forwarded-Host: <alternate-in-scope-host>`
- `X-Host: <alternate-in-scope-host>`
- `Forwarded: host=<alternate-in-scope-host>;proto=https`

## Evidence Required

- Baseline host behavior.
- Mutated host behavior.
- Impact: tenant confusion, poisoned link generation, upstream misroute, or cache/security policy delta.

## Stop

Stop before password-reset poisoning, invite poisoning, or cache poisoning beyond a safe owned-account proof.
