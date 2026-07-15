# Active Hunt Presence

> Short-lived, sanitized concurrency signal. This is not a task queue, agent
> transcript, MapStore entry, findings ledger, or historical record.

- Run ID:
- Program / family / lane:
- Owner / runner: `hermes-kanban` | `codex` | `claude-code` | `other`
- Started (UTC):
- Last checkpoint (UTC):
- Expires (UTC):
- Status: `starting` | `active` | `blocked` | `finished`
- Contact / handoff pointer:

## Current surface lease

- Flow, route cluster, host, or offline artifact slice:
- Current question / vulnerability lane:
- Mode: `cold-map` | `deep-test` | `verification` | `offline-analysis`
- Explicitly excluded overlapping work:

## Safety and handoff

- Scope/rate/account context reference:
- Attempts/artifact root:
- Targeted MapStore intent, if any: `app-facts` | `dedupe` | `coverage` | `none`
- Next checkpoint or release condition: