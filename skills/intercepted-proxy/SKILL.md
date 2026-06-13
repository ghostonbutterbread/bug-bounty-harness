---
name: intercepted-proxy
description: "Launch scoped browsers through the correct Caido proxy, enable live intercept or Tamper one lane at a time, modify selected requests, forward them, then disable intercept."
---

# Intercepted Proxy

Use when a live bug bounty task needs browser traffic routed through Caido and an agent must intercept, inspect, modify, forward, and clean up one request or request family.

This skill owns the operational proxy lifecycle. Use it before `/single-request-grabber` when the browser must be launched through the proxy first.

`chromium-test` should be the default browser launcher for this workflow. It prefers Playwright's bundled Chromium when available and routes launches through the runtime browser proxy by default.

Use intercept as the preferred live mode when the value of the test depends on seeing or changing a request while the browser flow is happening. This includes single-use tokens, nonce-bound requests, CSRF-bearing actions, signed one-shot flows, browser-generated state, and short critical state-changing flows where replaying later would be weaker or misleading.

Intercept can also be the fastest way to understand a live flow. When the history is noisy or the target request is buried in a multi-request browser action, pause the flow, forward unrelated requests, and inspect the target request family as it appears instead of relying only on passive history filtering afterward.

## Load Order

1. Read scope, owned-account context, and `live-testing-policy`.
2. Read `proxy-routing-policy` to resolve the current runtime lane.
3. Read `agent-proxy` for agent-lane work or `ryushe-proxy` only when Ryushe explicitly asks for his personal Caido lane.
4. Read `caido` to check MCP connectivity.
5. Read `chromium-test` or the relevant browser automation skill before launching a browser.
6. Read `pwnfox` when the task mentions a PwnFox color, profile, tab session,
   or phrase like "Red session"; use `X-PwnFox-Color: <color>` to isolate that
   lane in proxy history.
7. Read `$HARNESS_ROOT/prompts/intercepted-proxy-playbook.md`.
8. Route the security interpretation afterward:
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
trusted proxy CA in the isolated Chromium profile
```

For the harness launcher, prefer:

```bash
python3 "$HARNESS_ROOT/skills/chromium-test/scripts/chromium_test.py" <program> "<task>" \
  --url <target-url>
```

The launcher adds the runtime `--proxy-server` automatically and imports the mitmproxy CA into the isolated profile by default. Pass `--proxy-server` explicitly only when overriding the route table. Use `--proxy-cert-mode ignore` only for disposable debugging.

## When To Intercept

Prefer live intercept when:

- the action uses a single-use token, nonce, signed request, expiring CSRF token, or other fresh browser-generated value
- the request represents a single action item or short state-changing flow
- the test requires modifying one field before the server consumes the request
- the browser flow is noisy and the agent needs to identify the relevant request family in real time
- replaying from saved history would lose sequencing, timing, token freshness, or browser context

Prefer passive proxy history or direct replay when:

- the request is repeatable and does not depend on one-time state
- the goal is only request-shape review, comparison, or documentation
- the action can be reproduced safely with direct HTTP replay using agent-owned auth/session material

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
- Intercept only the minimum request family needed for the test; forward unrelated browser traffic without mutation.
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
- PwnFox color/header filter when used
- browser launch command shape or launcher JSON path
- whether `--proxy-server` was present and the proxy CA status was `trusted`; record explicit certificate-ignore fallback if used
- intercept/Tamper rule name, source, host/path condition, and sanitized mutation
- forwarded non-target request count
- target full URL, method, status, response type, and non-secret app state
- cleanup confirmation that intercept/rule is off
