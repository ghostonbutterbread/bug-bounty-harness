---
name: agent-proxy
description: "Resolve the default agent-lane Caido MCP endpoint for the current agent host."
---

# Agent Proxy

Use this when a bug bounty agent needs the normal agent-lane Caido MCP endpoint or proxy-observed traffic.

This is the default proxy lane. It should not inspect Ryushe's personal PC traffic. Use `ryushe-proxy` only when the task explicitly asks to view or compare Ryushe's traffic.

Phrase mapping: "your proxy", "agent proxy", "Ghost proxy", "OpenClaw proxy", or "local proxy" from the agent's point of view means this agent lane. "My proxy", "Ryushe's proxy", "my Caido", or "Ryushe's Caido" means the Ryushe lane instead; load `ryushe-proxy`.

If Ryushe says "look at the request <request>", the request lookup/source defaults to Ryushe's proxy unless he specifies another source. After that lookup, active agent testing still uses this agent lane by default. The only exception is when the agent is on the same host as Ryushe's proxy and `my proxy` resolves to `localhost` from that runtime. Rebuild the request with agent-owned browser/session state rather than replaying with Ryushe's cookies, tokens, or auth headers.

## Runtime Resolution

Resolve in this order:

1. Explicit task-provided MCP URL.
2. `GHOST_AGENT_RUNTIME`.
3. Hostname.
4. IP/interface fallback.
5. If ambiguous, stop and report the ambiguity.

## Defaults

- OpenClaw/Ghost machine: `http://hoster:3333/mcp`
- Hoster: `http://localhost:3333/mcp`
- Ryushe PC: `http://localhost:3333/mcp`
- AITestVM: use task-specific desktop/dynamic proxy when configured; otherwise use `http://hoster:3333/mcp`.

For browsers launched from the OpenClaw machine, load `openclaw-browser-proxy`; browser traffic should go through `http://hoster:8080`, while MCP remains `http://hoster:3333/mcp`.

## Guardrails

- Do not use `http://ryushespc:3333/mcp` from this skill.
- Do not treat an MCP URL as a browser proxy listener.
- Keep traffic lane labels in notes: agent lane, Ryushe lane, or desktop lane.
- Never print or store raw cookies, tokens, or auth headers from proxy traffic.
