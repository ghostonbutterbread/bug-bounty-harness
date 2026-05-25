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
4. Resolve the browser/account profile through Caido MCP first. With `--caido-profile auto`, ask Caido for the current profile/request authentication headers, especially `Authorization` and/or `Cookie`, then apply them to the launched browser/session update flow such as `mySession` without printing raw secrets. If Caido is offline or no profile tool is exposed, fall back only when the task can still be done safely.
5. Confirm the proxy/MCP setup:
   - MCP control endpoint defaults to `$KAIDO_MCP_PROXY_URL` or `http://127.0.0.1:3333/mcp`.
   - Browser proxy comes from the Caido profile when available.
   - Browser proxy uses `--proxy-server` or `$CHROMIUM_TEST_PROXY_SERVER` only as an override.
   - Any launch with a browser proxy must include `--ignore-certificate-errors`.

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

- Core posture: scoped testing is allowed; damaging behavior is explicit.
- Never reuse Ryushe's normal browser profile.
- Never print secrets, cookies, or credentials in chat.
- Prefer Caido MCP profile resolution over manually guessing accounts, profile directories, or proxy listeners.
- If Ryushe instructs authenticated testing, it is acceptable to use Caido-held `Authorization` and/or `Cookie` header values in memory to update the current scoped browser session, including `mySession`; this is not credential exfiltration unless values are printed, stored, reused outside scope, or sent elsewhere.
- With `--caido-profile auto`, dynamically pull usable auth headers from Caido's active profile/request context, not login credentials from history. Use `Authorization` and/or `Cookie` to update the browser session context, such as `mySession`, without writing the values to logs, shell output, findings, or prompts.
- Do not treat an MCP `/mcp` URL as a browser proxy server unless Caido returns it as an actual browser proxy listener.
- When a browser proxy is configured, verify the launch command includes `--ignore-certificate-errors` so proxy TLS interception works.
- Stay inside the program scope, account authorization, and rate limits.
- For state-changing tasks, confirm the action is allowed and non-destructive before proceeding.
