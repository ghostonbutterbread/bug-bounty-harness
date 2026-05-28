# Route Override Headers

Use when reverse-proxy or framework rewrite headers may route a benign visible path to a protected internal route.

## Checks

- Capture direct protected-path denial first.
- Send a benign visible URL with a route override header pointing at the protected path.
- Compare status, body length, route-specific headers, and downstream behavior.
- Keep tests read-only unless Ryushe approves a safe state-changing route.

## Mutations

- `X-Original-URL: /admin`
- `X-Rewrite-URL: /admin`
- `X-Forwarded-Prefix: /admin`
- `X-Forwarded-Uri: /admin`
- `X-Forwarded-Path: /admin`

## Evidence Required

- Direct protected-path baseline.
- Visible-path baseline.
- Mutated visible-path request.
- Reason the route/resource is owned, server/API-owned, or tied to approved test accounts.

## Stop

Stop if the route targets real-user data, billing controls, admin actions, or destructive functionality without explicit approval.
