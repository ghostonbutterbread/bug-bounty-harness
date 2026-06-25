---
name: bountylens
description: "Use BountyLens only for scope verification, target discovery, and program stats without per-agent MCP config."
---

# BountyLens

Use BountyLens only for:

- scope verification
- target discovery
- program stats

Do not use BountyLens as a source of hunt knowledge, notes, mapping, tested endpoint state, findings, report drafts, lifecycle state, or agent memory. Local files and Ghost's local bounty storage are canonical for all hunt knowledge.

## Core Decision

Do not require agents to add `@bountylens/mcp` to their MCP config. The package is a stdio MCP wrapper around the BountyLens REST API, so agents should use the direct API helper in this skill unless Ryushe explicitly asks for MCP-client wiring.

BountyLens never takes precedence over local hunt knowledge. If BountyLens data conflicts with local files, treat local files as authoritative and mention the conflict instead of overwriting, replacing, or ignoring local context.

Canonical local knowledge routes:

- `/bounty-storage` resolves the active Bounty Core family/lane and canonical directories.
- `/map-store` stores URL-anchored, surface-wide, and app-wide observations,
  mapped surfaces, tested state, and reusable endpoint/app behavior.
- `/bounty-notes` stores timeline entries, hypotheses, handoffs, FAQs, and
  human-readable investigation narrative.
- `/js` owns JavaScript endpoint, source/sink, source map, and JS-derived wordlist knowledge.
- `/mental-map` owns application flow mapping, proxy-derived route grouping, and sequence/context notes.
- Target directories under `~/Shared/bounty_recon/{program}/` and `~/Shared/bounty/{program}/` hold durable evidence, reports, ledgers, and agent outputs.

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
3. Treat BountyLens as an external system. Before writing any entry, finding, or report draft to BountyLens, check for PII, real secrets, cookies, tokens, private customer data, and accidental sensitive file contents.
4. Use full URLs for endpoints in findings, leads, tested entries, and reports whenever the target has a known base URL.
5. Do not delete sessions, entries, or reports unless Ryushe explicitly asks for deletion in the current task.
6. Do not mark a report `submitted` unless Ryushe explicitly says it was submitted or asks you to set that status.
7. Do not read BountyLens for hunt notes, findings, tested endpoints, report drafts, or agent memory unless Ryushe explicitly asks for a BountyLens audit/export.
8. Do not write findings, evidence, notes, report drafts, tested endpoint state, or lifecycle state to BountyLens from normal hunting workflows.
9. Local Ghost ledgers and local files are the primary and default write target. Agents must record new findings, evidence, report material, mapped surfaces, tested endpoint state, and lifecycle state through the normal Ghost pipeline first, usually `/bounty-storage`, `/map-store`, `/bounty-notes`, `manual_hunter.py`, `me_ledger.py`, or the target lane's canonical ledger/report helpers.
10. If BountyLens is used alongside local files, report local ledger/report/map paths first. BountyLens can supply program/scope/stat context, but local canonical evidence belongs in the relevant project or bounty directory.

## Workflow

1. Verify the helper can load configuration without exposing secrets:
   ```bash
   python3 skills/bountylens/scripts/bountylens_api.py --check
   ```
2. For allowed reads, use the direct helper:
   ```bash
   python3 skills/bountylens/scripts/bountylens_api.py GET /programs --query q=shopify
   python3 skills/bountylens/scripts/bountylens_api.py GET /watchlist
   python3 skills/bountylens/scripts/bountylens_api.py GET /stats
   ```
3. Before using BountyLens data in a hunt, resolve local context first through `/bounty-storage`, `/map-store`, and the relevant lane skill such as `/js` or `/mental-map`.
4. Report back with local ledger/report/map paths first. If BountyLens supplied scope, discovery, or stat context, include only the relevant non-secret program/scope/stat details. Do not include the API token or raw auth headers.

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
- The task needs hunt knowledge, mapped endpoints, tested endpoint state, findings, report drafts, notes, or agent memory. Use local files, `/bounty-storage`, `/map-store`, `/js`, `/mental-map`, or the relevant local lane skill instead.
- An agent is about to write a new finding or report only to BountyLens without first recording it in the local Ghost ledger/report pipeline.
- A normal hunt workflow is about to use BountyLens instead of local files as the source of truth.
- A BountyLens write was not explicitly requested by Ryushe as a BountyLens-specific operation.
- A requested write would include secrets, cookies, tokens, private customer data, or unreviewed sensitive files.
- A requested delete or `submitted` status change was not explicitly approved by Ryushe in the current task.
- The API returns an ownership, subscription, authentication, or rate-limit error that changes the expected workflow.
