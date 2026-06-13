---
name: bountylens
description: "Use BountyLens sessions, findings, leads, tested endpoints, reports, watchlist, stats, and program intelligence without per-agent MCP config."
---

# BountyLens

Use when a task needs to read or write BountyLens hunt sessions, findings, leads, tested endpoints, notes, report drafts, program records, watchlist, recommendations, or hunter stats.

## Core Decision

Do not require agents to add `@bountylens/mcp` to their MCP config. The package is a stdio MCP wrapper around the BountyLens REST API, so agents should use the direct API helper in this skill unless Ryushe explicitly asks for MCP-client wiring.

Token source:

```text
~/.env
```

Expected variables:

```text
BOUNTYLENS_API_KEY=bl_...
BOUNTYLENS_URL=https://bountylens.com
```

`BOUNTYLENS_URL` is optional and defaults to `https://bountylens.com`.

## Required Rules

1. Never print, paste, commit, summarize, or expose `BOUNTYLENS_API_KEY` or raw `~/.env` contents.
2. Do not shell-source `~/.env`; use `scripts/bountylens_api.py`, which parses key/value lines without executing the file.
3. Treat BountyLens as an external system. Before writing reports or findings, check for PII, real secrets, cookies, tokens, private customer data, and accidental sensitive file contents.
4. Use full URLs for endpoints in findings, leads, tested entries, and reports whenever the target has a known base URL.
5. Do not delete sessions, entries, or reports unless Ryushe explicitly asks for deletion in the current task.
6. Do not mark a report `submitted` unless Ryushe explicitly says it was submitted or asks you to set that status.
7. Keep local Ghost findings and BountyLens entries consistent when both are in use: BountyLens can be the dashboard/log, but local canonical evidence still belongs in the relevant project or bounty directory.

## Workflow

1. Verify the helper can load configuration without exposing secrets:
   ```bash
   python3 skills/bountylens/scripts/bountylens_api.py --check
   ```
2. For reads, use the direct helper:
   ```bash
   python3 skills/bountylens/scripts/bountylens_api.py GET /sessions --query status=active
   python3 skills/bountylens/scripts/bountylens_api.py GET /watchlist
   python3 skills/bountylens/scripts/bountylens_api.py GET /programs --query q=shopify
   ```
3. For writes, prepare a minimal JSON payload and send it through the helper:
   ```bash
   python3 skills/bountylens/scripts/bountylens_api.py POST /sessions/123/entries \
     --data-json '{"type":"lead","title":"Interesting redirect behavior","endpoint":"https://example.com/path","method":"GET","description":"Observed redirect parameter behavior; needs validation."}'
   ```
4. For report drafts, prefer reading the local markdown report file and wrapping it in JSON with a short script or `jq`, then POST to:
   ```text
   /sessions/{session_id}/reports
   ```
5. Report back with BountyLens object IDs, titles, session IDs, and non-secret status. Do not include the API token or raw auth headers.

## Useful Endpoints

Sessions:

```text
GET    /sessions
POST   /sessions
GET    /sessions/{session_id}
PUT    /sessions/{session_id}
DELETE /sessions/{session_id}
```

Entries:

```text
GET    /sessions/{session_id}/entries
POST   /sessions/{session_id}/entries
POST   /sessions/{session_id}/entries/bulk
PUT    /sessions/{session_id}/entries/{entry_id}
DELETE /sessions/{session_id}/entries/{entry_id}
```

Reports:

```text
GET    /sessions/{session_id}/reports
POST   /sessions/{session_id}/reports
PUT    /sessions/{session_id}/reports/{report_id}
DELETE /sessions/{session_id}/reports/{report_id}
```

Programs and intelligence:

```text
GET /programs?q={query}
GET /programs/{handle}
GET /recommend
GET /watchlist
GET /stats
```

## MCP Compatibility

Only use this path when a task specifically needs a real MCP server process, for example manual integration testing with an MCP client:

```bash
npx -y @bountylens/mcp
```

The process expects `BOUNTYLENS_API_KEY` and optionally `BOUNTYLENS_URL` in its environment. Prefer passing those from the current process environment or a secret-aware launcher. Do not add the server to global Claude/Codex/OpenClaw MCP config just to make BountyLens available to agents.

## Stop Conditions

- `BOUNTYLENS_API_KEY` is missing from the environment and `~/.env`.
- A requested write would include secrets, cookies, tokens, private customer data, or unreviewed sensitive files.
- A requested delete or `submitted` status change was not explicitly approved by Ryushe in the current task.
- The API returns an ownership, subscription, authentication, or rate-limit error that changes the expected workflow.
