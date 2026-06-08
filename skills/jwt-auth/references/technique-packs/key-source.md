# Key Source

Use when JWT verification may trust attacker-controlled key material through `kid`, `jku`, `x5u`, `x5c`, `x5t`, inline `jwk`, or JWKS discovery.

## Checks

- Map key-selection inputs: header `kid`, discovery JWKS URL, certificate URL, inline JWK, or thumbprint.
- For `kid`, test simple key IDs, traversal-shaped values, and URL-shaped values only enough to prove lookup behavior.
- For `jku` or `x5u`, host an owned JWKS/certificate endpoint and sign with the matching private key.
- For inline `jwk`, include only attacker-controlled public key material in the header and sign with the matching private key.
- For `x5c`/`x5t`, test whether the server trusts embedded certificate material or thumbprints without pinning.

## Evidence Required

- Server accepts a token signed by attacker-controlled key material or selected through attacker-controlled key reference.
- Callback logs or response deltas show the key source was used.
- The token grants protected role, scope, tenant, or object access.

## Stop

Stop before reading real local files, probing internal URLs, or using third-party key infrastructure. Route URL-fetch behavior to `/ssrf`.
