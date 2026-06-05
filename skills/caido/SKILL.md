---
name: caido
description: "Connect to a Caido MCP instance for proxy traffic inspection and request comparison."
---

# Caido

Use this when a bug bounty task needs Caido MCP traffic, project history, request inspection, or request comparison.

## MCP URL

Default to:

```text
http://localhost:3333/mcp
```

If the user gives a hostname or IP address, use:

```text
http://<hostname-or-ip>:3333/mcp
```

If the user gives a full URL, use that exact URL.

## Workflow

1. Resolve the MCP URL from the user's request.
2. Check connectivity before assuming Caido is available.
3. If the task mentions PwnFox, a colored browser/profile/session, or a phrase
   like "Red session", load `/pwnfox` and filter history by
   `X-PwnFox-Color: <color>`.
4. If unreachable, report whether it looks like host, firewall, bind-address, or port exposure trouble.
5. For comparisons, keep Caido projects isolated and compare equivalent workflows request-by-request.
6. For one live owned-session request capture or intercept/modify testing, route to `/single-request-grabber` after Caido connectivity is confirmed.
