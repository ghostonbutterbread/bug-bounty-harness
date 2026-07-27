---
name: agent-proxy
description: "Lease and use the task-scoped agent MITM listener that captures active agent traffic."
---

# Agent Proxy

Use this when an agent needs to send active browser/API traffic or inspect the agent’s own proxy history.

## Rule

The agent lane is a task-scoped local `mitmproxy`/`mitmdump` listener—not Caido. Ryushe’s Caido is a separate read-only source-history lane; load `ryushe-proxy` only when Ryushe explicitly asks to inspect/compare his traffic or refresh a named approved auth seed.

## Lease Before Traffic

For each task, record a unique run ID, local/leased MITM host:port, flow-file path, CA/profile path, account boundary, and stop/cleanup condition.

On Hoster, lease an available loopback listener in `8081-8090`. Do not use port `8080`; it is not the agent MITM lane. Keep the MITM service and flow file owner-restricted because captured flows can contain session material.

Route all active work through that listener:

```text
curl/httpx/scripts: http://127.0.0.1:<leased-port>
browser: --proxy-server=http://127.0.0.1:<leased-port>
```

Trust the task MITM CA in the isolated browser profile. Parse or inspect the task flow file for agent history, then stop the task-owned listener and securely retain/reject its capture at completion.

## Source vs Replay

A request from Ryushe’s Caido is source evidence only. Rebuild its non-secret shape with the agent’s owned account/session and replay it through the task MITM listener. Label artifacts `source: Ryushe Caido` and `replay: agent MITM`.

## Guardrails

- Never send active agent traffic through Caido or a Caido MCP endpoint.
- Never treat an MCP endpoint as an HTTP proxy.
- Do not use a shared listener without a recorded lease.
- Do not print or store raw cookies, tokens, authorization headers, or private request bodies outside locked-down auth seeds/flow artifacts.
