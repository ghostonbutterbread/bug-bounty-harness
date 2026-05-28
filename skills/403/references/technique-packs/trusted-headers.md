# Trusted Headers

Use when reverse-proxy or framework headers may alter the route, method, host, or client context for a `403` endpoint.

## Checks

- Route rewrite headers such as `X-Original-URL` and `X-Rewrite-URL`.
- Proxy/client context headers such as `X-Forwarded-For`, `X-Real-IP`, and `Forwarded`.
- Method override headers such as `X-HTTP-Method-Override`.
- Host routing headers such as `X-Forwarded-Host`.

## Route

Load `/headers` for deeper lane-specific guidance:

- route override -> `/headers` route-override
- proxy trust -> `/headers` proxy-trust
- method override -> `/headers` method-override
- host routing -> `/headers` host-routing

## Evidence Required

- Direct `403` baseline.
- Header-mutated request.
- Reason the route/resource is safe to probe.
- Security-relevant response delta.

## Stop

Stop before state-changing subroutes unless Ryushe approved the test and the target resource is an approved test-account resource.
