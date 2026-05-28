# 403 Context Pack

Use this as the compact branch map for `/403`.

## Rules

- Only use this after a concrete `403` is observed in the current owned context.
- The resource must be agent-owned, assigned server/API surface, or tied to Ryushe's approved test account set.
- Do not use 403 bypasses against real-user accounts, tenants, files, orders, profiles, workspaces, or other non-owned resources.
- Stop when the observed block is rate limiting, bot protection, CAPTCHA, WAF enforcement, or explicit target policy.

## Branch Map

### Path Normalization

Load when the protected route may be inconsistently normalized by proxy, CDN, framework, or application router.

Reference:
- `$HARNESS_ROOT/skills/403/references/technique-packs/path-normalization.md`

### Trusted Headers

Load when reverse-proxy, route rewrite, method override, or client-IP headers may affect route authorization.

Reference:
- `$HARNESS_ROOT/skills/403/references/technique-packs/trusted-headers.md`

Related skill:
- `/headers`

### Auth State

Load when the same endpoint behaves differently across unauthenticated, intended-role, and approved alternate test-account sessions.

Reference:
- `$HARNESS_ROOT/skills/403/references/technique-packs/auth-state.md`

Related skills:
- `/access-control`
- `/idor`
