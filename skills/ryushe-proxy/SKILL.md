---
name: ryushe-proxy
description: "Inspect or compare Ryushe's personal Caido traffic from an approved Hoster agent."
---

# Ryushe Proxy

Use this only when the task explicitly asks to view, inspect, or compare Ryushe's personal Caido traffic.

This is not the default agent proxy. Normal spawned agents should use `agent-proxy`.

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
5. Compare equivalent flows against the agent lane when needed.

## Guardrails

- Read/compare by default; do not mutate Ryushe's Caido projects unless requested.
- Do not copy cookies, bearer tokens, API keys, or other secrets from Ryushe's proxy into agent browsers/API clients unless Ryushe explicitly approves that action.
- Do not print, persist, or paste raw secrets from Ryushe's traffic into prompts, chat, logs, findings, reports, commits, or notes.
- Keep Ryushe-lane evidence labeled separately from agent-lane evidence.
