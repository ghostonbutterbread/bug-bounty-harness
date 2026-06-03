---
name: intercepted-proxy
description: "Launch scoped browsers through the correct Caido proxy, enable live intercept or Tamper one lane at a time, modify selected requests, forward them, then disable intercept."
---

# Intercepted Proxy

Use when a live bug bounty task needs browser traffic routed through Caido and an agent must intercept, inspect, modify, forward, and clean up one request or request family.

This skill owns the operational proxy lifecycle. Use it before `/single-request-grabber` when the browser must be launched through the proxy first.

## Load Order

1. Read scope, owned-account context, and `live-testing-policy`.
2. Read `proxy-routing-policy` to resolve the current runtime lane.
3. Read `agent-proxy` for agent-lane work or `ryushe-proxy` only when Ryushe explicitly asks for his personal Caido lane.
4. Read `caido` to check MCP connectivity.
5. Read `chromium-test` or the relevant browser automation skill before launching a browser.
6. Read `$HARNESS_ROOT/prompts/intercepted-proxy-playbook.md`.
7. Route the security interpretation afterward:
   - one fresh request/body/token -> `/single-request-grabber`
   - authz/object changes -> `/access-control` or `/idor`
   - payment/billing -> `/payment-testing`
   - headers/request-shape -> `/headers`

## Runtime Proxy Rules

- OpenClaw/Ghost/`ghostonbread`:
  - browser proxy: `http://hoster:8080`
  - Caido MCP: `http://hoster:3333/mcp`
- Hoster:
  - browser proxy: `http://localhost:8080`
  - Caido MCP: `http://localhost:3333/mcp`
- Ryushe PC / `ryushespc` / Abommie:
  - browser proxy: `http://localhost:8080`
  - Caido MCP: `http://localhost:3333/mcp`

Never pass a `/mcp` URL as a browser proxy. Browser proxy and Caido MCP are different listeners.

If `hoster` does not resolve from OpenClaw, check the route table at `/home/ryushe/projects/ai-policies/skills/proxy-routing-policy/data/proxy_routes.json` instead of guessing.

## Browser Launch Requirements

Any spawned Chromium/Chrome browser used for intercept testing must include:

```text
--proxy-server=<resolved-browser-proxy>
--ignore-certificate-errors
```

For the harness launcher, prefer:

```bash
python3 "$HARNESS_ROOT/skills/chromium-test/scripts/chromium_test.py" <program> "<task>" \
  --proxy-server <resolved-browser-proxy> \
  --url <target-url>
```

Use `--caido-profile auto` only when the profile tool returns a real browser proxy listener. If it does not, pass `--proxy-server` explicitly from the runtime route.

## Intercept Lifecycle

1. Resolve and verify the browser proxy and Caido MCP endpoints.
2. Launch or confirm the browser is using the proxy flag.
3. Enable Caido intercept or create one scoped Tamper rule with source `INTERCEPT`.
4. Trigger exactly one browser action or short flow.
5. Forward non-target requests needed for the flow.
6. Pause or match only the target request/family.
7. Modify one approved field, header, method, query parameter, or body value.
8. Forward the request once and observe the app response/state.
9. Disable intercept or disable/delete the temporary Tamper rule immediately.
10. Confirm no Ghost intercept/tamper rule remains active.
11. Record a sanitized action trail.

## Guardrails

- One proxy lane at a time unless Ryushe confirms enough proxies are available.
- One mutation family at a time.
- Keep rules scoped to exact host/path/request family when possible.
- Do not leave intercept or Tamper rules enabled after the lane.
- Do not log cookies, bearer tokens, auth headers, CSRF tokens, card data, payment tokens, raw credentials, or private request bodies.
- Stop if the browser is not actually proxied, if intercept cannot be disabled cleanly, or if the next step would spend money, modify non-owned data, trigger human review, or create irreversible impact.

## Evidence

Write notes under the owning skill lane, usually:

```text
$HARNESS_SHARED_BASE/{program}/ghost/<owning-skill>/
```

Record:

- runtime hostname and resolved lane
- browser proxy and Caido MCP endpoint, without secrets
- browser launch command shape or launcher JSON path
- whether `--proxy-server` and `--ignore-certificate-errors` were present
- intercept/Tamper rule name, source, host/path condition, and sanitized mutation
- forwarded non-target request count
- target full URL, method, status, response type, and non-secret app state
- cleanup confirmation that intercept/rule is off
