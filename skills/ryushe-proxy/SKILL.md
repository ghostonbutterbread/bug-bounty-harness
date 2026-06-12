---
name: ryushe-proxy
description: "Inspect or compare Ryushe's personal Caido traffic from an approved Hoster agent."
---

# Ryushe Proxy

Use this when the task explicitly asks to view, inspect, or compare Ryushe's personal Caido traffic.

This is not the default agent proxy. Normal spawned agents should use `agent-proxy`.

Phrase mapping: "my proxy", "Ryushe's proxy", "my Caido", or "Ryushe's Caido" means this Ryushe lane. "Look at the request <request>" also means inspect the matching request in Ryushe's proxy by default unless Ryushe names a different source. "Your proxy", "agent proxy", "Ghost proxy", "OpenClaw proxy", or "local proxy" from the agent's point of view means the agent lane instead; load `agent-proxy`.

## Capture vs Testing Lane

Use this skill for source lookup by default. If an agent needs to test the application after pulling a request from Ryushe's proxy, replay through the agent lane with `agent-proxy` unless the same-host exception applies.

Same-host exception: active testing may use Ryushe's proxy only when the agent is running on the same host as the proxy and `my proxy` resolves to `localhost` from that agent runtime. Verify the runtime/hostname and resolved endpoint before testing. If the endpoint resolves to `ryushespc`, a tunnel, or any remote host, this skill remains source lookup only.

Do not replay from Ryushe's proxy just because the request was found there. Treat the Ryushe-lane request as a shape/template: method, full URL, parameters, body structure, and non-secret headers. Use agent-owned cookies, tokens, browser state, and test-account resources for active replay.

For replaying that request shape, prefer direct HTTP replay from the agent with `curl`, `httpx`, or a focused script. If direct replay fails because it looks like non-browser traffic, the agent may use its own local MCP/proxy replay fallback. That fallback is still agent-lane, not Ryushe-lane, unless the same-host localhost exception applies.

## Named-Account Auth Refresh

Ryushe has approved a narrow exception for named account/color refreshes.

If Ryushe explicitly asked to use a named account or color, for example
`blue credentials`, and the registered auth seed for that same account is
missing, stale, or fails in a fresh Chromium/MITM browser, the agent may use
Ryushe's proxy to refresh that account's auth seed when all of these are true:

- `credentials/account_inventory.json` resolves the requested alias/color to a
  specific account.
- That account record has `auth_refresh_source=ryushe-proxy`.
- The lookup is constrained by a non-secret hint such as `pwnfox:blue`,
  `account:blue-primary`, host, or program context.
- The refreshed values are written only to the account's locked-down auth seed
  file referenced by `auth_seed_ref` or `credential_ref`.

The agent must not print, summarize, commit, paste, or otherwise persist the
raw cookies, bearer tokens, CSRF tokens, or private headers. After refreshing the
seed, retry active testing through the agent MITM lane, not through Ryushe's
proxy, unless Ryushe explicitly asks for same-host active testing.

## Endpoint

From Hoster only:

```text
http://ryushespc:3333/mcp
```

If the current agent is not running on Hoster, do not try to reach this endpoint directly. Report that Ryushe-lane proxy access is Hoster-only unless Ryushe approves a tunnel or alternate route.

Current boundary note: the Ghost/OpenClaw host, also referred to as `ghostonbread`, cannot currently connect to `http://ryushespc:3333/mcp`. Agents running there must not attempt direct Ryushe-proxy access; they should use `agent-proxy` for Hoster/agent-lane traffic and ask for a Hoster agent or approved tunnel if Ryushe-lane comparison is needed.

## Workflow

1. Confirm the task explicitly asks for Ryushe-lane traffic review or comparison.
2. Confirm the agent is running on Hoster by `GHOST_AGENT_RUNTIME=hoster`, hostname, or a trusted runtime note.
3. Connect to `http://ryushespc:3333/mcp`.
4. Inspect only the relevant project/history/workflow requested.
5. For approved named-account refresh, update only the locked-down auth seed
   for that account, then close the Ryushe-proxy lookup path.
6. For active testing, switch to the agent MITM/proxy lane unless the same-host
   localhost exception applies.
7. Compare equivalent flows against the agent lane when needed.

## Guardrails

- Read/compare by default; do not mutate Ryushe's Caido projects unless requested.
- Do not actively test through Ryushe's proxy unless the current agent is on the same host as the proxy and `my proxy` resolves to `localhost`.
- Do not copy cookies, bearer tokens, API keys, or other secrets from Ryushe's proxy into agent browsers/API clients unless Ryushe explicitly approves that action. The standing approval in this skill applies only to named-account auth refresh records with `auth_refresh_source=ryushe-proxy`.
- Do not print, persist, or paste raw secrets from Ryushe's traffic into prompts, chat, logs, findings, reports, commits, or notes.
- Keep Ryushe-lane evidence labeled separately from agent-lane evidence.
