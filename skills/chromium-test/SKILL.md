---
name: chromium-test
description: "Launch an isolated Chromium test browser on a free local CDP port for scoped web, desktop, or proxy-observed bug bounty workflows."
---

# Chromium Test

Use when a task needs a fresh Chromium/Chrome instance with remote debugging enabled, an isolated profile, and proxy/MCP-aware observation.

## Invocation

```text
/chromium-test <program> <task> [--caido-profile <name|auto>] [--url <url>] [--port <port>]
/chromium-test superdrug pfp
/chromium-test canva upload-flow --caido-profile qa-primary --url https://www.canva.com/
```

## Required Preflight

1. Read program scope/rules and the interpreted rate limit before live interaction.
2. Read `$HARNESS_ROOT/prompts/chromium-test-playbook.md`.
3. Check existing program context under `$HARNESS_SHARED_BASE/{program}/`.
4. Resolve the browser/account profile through Caido MCP first. If Caido is offline or no profile tool is exposed, fall back only when the task can still be done safely.
5. Confirm the proxy/MCP setup:
   - MCP control endpoint defaults to `$KAIDO_MCP_PROXY_URL` or `http://127.0.0.1:3333/mcp`.
   - Browser proxy comes from the Caido profile when available.
   - Browser proxy uses `--proxy-server` or `$CHROMIUM_TEST_PROXY_SERVER` only as an override.

## Canonical Files

- Playbook: `$HARNESS_ROOT/prompts/chromium-test-playbook.md`
- Launcher: `$HARNESS_ROOT/skills/chromium-test/scripts/chromium_test.py`
- Profiles: `$HARNESS_SHARED_BASE/{program}/ghost/chromium-test/profiles/`
- Notes/evidence: `$HARNESS_SHARED_BASE/{program}/ghost/chromium-test/`

## Workflow

1. Start an isolated browser with the launcher:
   ```bash
   python3 "$HARNESS_ROOT/skills/chromium-test/scripts/chromium_test.py" <program> "<task>" --caido-profile auto
   ```
2. Use the returned CDP URL to connect browser automation or manual debugging.
3. Perform only the requested scoped action in that browser profile.
4. Observe traffic through the approved proxy/MCP workflow when configured.
5. Save screenshots, request notes, and reproduction details under the program evidence directory.

## Guardrails

- Never reuse Ryushe's normal browser profile.
- Never print secrets, cookies, or credentials in chat.
- Prefer Caido MCP profile resolution over manually guessing accounts, profile directories, or proxy listeners.
- Do not treat an MCP `/mcp` URL as a browser proxy server unless Caido returns it as an actual browser proxy listener.
- Stay inside the program scope, account authorization, and rate limits.
- For state-changing tasks, confirm the action is allowed and non-destructive before proceeding.
