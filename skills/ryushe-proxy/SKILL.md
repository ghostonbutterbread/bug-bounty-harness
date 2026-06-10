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
5. For active testing, switch to `agent-proxy` and replay from the agent lane unless the same-host localhost exception applies.
6. Compare equivalent flows against the agent lane when needed.

## Guardrails

- Read/compare by default; do not mutate Ryushe's Caido projects unless requested.
- Do not actively test through Ryushe's proxy unless the current agent is on the same host as the proxy and `my proxy` resolves to `localhost`.
- Do not copy cookies, bearer tokens, API keys, or other secrets from Ryushe's proxy into agent browsers/API clients unless Ryushe explicitly approves that action.
- Do not print, persist, or paste raw secrets from Ryushe's traffic into prompts, chat, logs, findings, reports, commits, or notes.
- Keep Ryushe-lane evidence labeled separately from agent-lane evidence.
