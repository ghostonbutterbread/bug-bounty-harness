---
name: caido
description: "Inspect Ryushe’s Caido history as read-only source evidence; never use it as active agent transport."
---

# Caido

Use this only when a task explicitly needs Ryushe’s personal Caido project/history, a PwnFox-colored source request, or a named account’s approved auth refresh source.

## Boundary

Caido is **source history**, not the agent proxy. Agents poll the relevant Ryushe-Caido history from an approved Hoster context, copy only the minimum non-secret request shape needed to understand a flow, and perform every active replay/browser action through the task-scoped agent MITM listener.

Do not require a Caido MCP connection for normal active testing. Do not route curl, httpx, scripts, browsers, intercepts, or replays through Caido.

## Source Workflow

1. Confirm Ryushe explicitly requested personal-Caido inspection/comparison or named account/color context.
2. From the approved Hoster context, query only the relevant program, host, PwnFox color, route, or workflow.
3. Extract only method, URL, parameter/body shape, and necessary non-secret headers.
4. If the selected account record permits `auth_refresh_source=ryushe-proxy`, refresh only its registered locked-down auth seed.
5. Close the Caido lookup and switch to the task MITM listener for live work.

## Evidence

Keep source and replay distinct:

```text
source: Ryushe Caido
replay: agent MITM
```

Never print raw cookies, bearer tokens, CSRF values, API keys, or private bodies from Caido.