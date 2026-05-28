# Path Normalization

Use when a `403` may result from mismatched normalization between CDN, reverse proxy, router, framework, and application authorization checks.

## Checks

- trailing slash
- duplicated slash
- dot segments
- encoded slash and double-encoded slash
- semicolon path parameters
- suffix or prefix changes
- mixed case when the stack is case-sensitive upstream and insensitive downstream

## Evidence Required

- Direct protected-path baseline.
- Mutated path request.
- Response delta showing route reachability or protected behavior, not just a different error page.

## Stop

Stop if the route targets real-user data, destructive functionality, billing controls, or out-of-scope paths.
