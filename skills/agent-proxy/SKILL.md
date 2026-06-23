---
name: agent-proxy
description: "Resolve the default agent-lane Caido MCP endpoint for the current agent host."
---

# Agent Proxy

Use this when a bug bounty agent needs the normal agent-lane Caido MCP endpoint or proxy-observed traffic.

This is the default proxy lane. It should not inspect Ryushe's personal PC traffic. Use `ryushe-proxy` only when the task explicitly asks to view or compare Ryushe's traffic.

Phrase mapping: "your proxy", "agent proxy", "Ghost proxy", "OpenClaw proxy", or "local proxy" from the agent's point of view means this agent lane. "My proxy", "Ryushe's proxy", "my Caido", or "Ryushe's Caido" means the Ryushe lane instead; load `ryushe-proxy`.

If Ryushe says "look at the request <request>", the request lookup/source defaults to Ryushe's proxy unless he specifies another source. After that lookup, active agent testing still uses this agent lane by default. The only exception is when the agent is on the same host as Ryushe's proxy and `my proxy` resolves to `localhost` from that runtime. Rebuild the request with agent-owned browser/session state rather than replaying with Ryushe's cookies, tokens, or auth headers.

Replay transport policy: direct HTTP replay with `curl`, `httpx`, or a focused script is preferred for known request shapes. Use the agent-lane MCP/proxy replay only as a fallback when direct replay fails for browser/proxy/client-fingerprint reasons such as Cloudflare or browser-only flow state. Live browser exploration still uses Chromium/Playwright attached to the agent's local browser proxy.

Default MITM policy: generic `curl`, `httpx`, and script traffic should go
through the resolved agent MITM proxy so requests are recorded. On
OpenClaw/Ghost this is normally `-x http://hoster:8080`; on Hoster or
Ryushe's PC this is normally `-x http://localhost:8080`. Spawned agents that
need isolated traffic should lease a task-specific MITM lane, currently
`8081-8090` on Hoster, then index the lane into the central proxy store and
release the lease before finishing.

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

For direct replay from the OpenClaw machine, use `curl -x http://hoster:8080`
or the equivalent `httpx`/script proxy setting unless a leased per-agent lane
has been assigned.

## Guardrails

- Do not use `http://ryushespc:3333/mcp` from this skill.
- Do not treat an MCP URL as a browser proxy listener.
- Keep traffic lane labels in notes: agent lane, Ryushe lane, or desktop lane.
- Index task-specific MITM lanes into the proxy store before release when they
  contain useful traffic.
- Never print or store raw cookies, tokens, or auth headers from proxy traffic.
