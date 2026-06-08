# JWT Auth Playbook

Use this after `/jwt-auth` classifies the lane or when writing a report.

## Safety Boundary

- In-scope target only.
- Owned account/resource only.
- Redact full JWTs, signatures, cookies, secrets, and private claims in chat.
- One mutation family at a time.
- Offline weak-secret checks are okay against owned/lab tokens; do not run live brute force.
- URL-based `iss`, `jku`, and `x5u` tests must use owned callback/JWKS infrastructure.

## Method

1. Capture baseline request and response with the original token.
2. Decode header and payload without trusting them.
3. Identify the likely enforcement input: signature, key lookup, claim, expiry, or parser behavior.
4. Load one reference pack from `prompts/jwt-auth-context-pack.md`.
5. Create the smallest mutated token needed for that lane.
6. Replay once or a few times at low rate, compare to denied and allowed baselines, then minimize.
7. If the route is object/tenant-specific, hand off to `/access-control` or `/idor` with the token mutation and owned resource map.

## Report Fields

- full URL and request method
- token location: Authorization header, cookie, query, body, storage, or websocket
- safe decoded header/payload before and after mutation
- loaded reference pack
- exact mutation family
- baseline denied response
- successful response delta
- affected role, scope, tenant, object, or auth-state boundary
- owned account/resource proof
- cleanup and stop condition
