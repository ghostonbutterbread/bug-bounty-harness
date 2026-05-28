# Auth State

Use when a `403` may depend on session state, role, tenant, subscription, or approved account relationship.

## Checks

- logged-out baseline
- intended-role approved account
- alternate approved account
- expired/stale session
- cookie-only vs header-only auth when already approved for the account set

## Route

- object ownership -> `/idor`
- role or tenant boundary -> `/access-control`
- mixed cookie/header identity -> `/headers` auth-context

## Evidence Required

- Account aliases and ownership.
- Destructible status if actions are involved.
- Baseline and comparison responses.
- Boundary changed by the mutation.

## Stop

Stop immediately if the test reaches or targets a real user's private resource.
