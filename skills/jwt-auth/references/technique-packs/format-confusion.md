# Format Confusion

Use when JWT parsing, serialization, nested token handling, JWE/JWS confusion, duplicate claims, whitespace, or base64url formatting may affect verification or authorization.

## Checks

- Test duplicate claim precedence only with harmless owned-account values.
- Try JSON type changes: string to array, null, boolean, or object when the claim parser may coerce types.
- Try base64url padding, extra whitespace, and extra dot segments only enough to classify parser behavior.
- For nested JWTs, check whether an inner unsigned or differently signed token is trusted.
- For JWE/JWS confusion, check whether encrypted-looking tokens bypass signature validation or whether signed tokens are accepted where encrypted tokens are required.

## Evidence Required

- Parser variation changes protected authorization or token acceptance.
- The minimized malformed/nested/format variant is reproducible.
- Protected impact is tied to auth, role, tenant, or object access.

## Stop

Stop if results are only parse errors, generic 500s, or no protected behavior difference.
