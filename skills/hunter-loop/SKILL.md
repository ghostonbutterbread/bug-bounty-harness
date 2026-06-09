---
name: hunter-loop
description: "Use when orchestrating a goal-driven bounty-hunter loop that maps an app, maintains target memory, and dispatches scoped specialist agents."
---

# Hunter Loop

Use this when Ryushe wants Hackbot to behave like a bounty hunter instead of a
scanner: map broadly, learn from each attempt, then send focused specialists
only when the app surface justifies it.

Hunter Loop is the parent orchestration skill. It does not replace `/xss`,
`/access-control`, `/idor`, `/jwt-auth`, `/ato`, `/payment-testing`,
`/deep-hunt`, `/live-map`, or `/hunter-memory`; it decides when to invoke them
and what scoped packet they should receive.

## Load Order

1. Read scope, account/resource context, and the active live-testing policy.
2. Read `$HARNESS_ROOT/prompts/hunter-loop-playbook.md`.
3. Load existing state when present:
   - `/hunter-memory` summaries for the program or surface
   - `/live-map` application-map summary and handoff packets
   - `/url-ingest` stats/history for route and parameter review depth
   - program knowledge and prior findings
4. Start or resume a target memory pack.
5. Map one app area at a time, then dispatch specialists on evidence-backed
   triggers.

## Commands

```text
/hunter-loop <program> --goal <objective>
/hunter-loop <program> --section <section-or-flow> --goal <objective>
/hunter-loop <program> --from-live-map --goal <objective>
/hunter-loop <program> --benchmark <lab-name> --goal <objective>
```

This skill currently defines the orchestration protocol. Use existing mapping,
browser, proxy, Hunter Memory, and vulnerability-lane skills for concrete
actions.

## Orchestrator Rule

The parent agent owns:

- application map
- target memory pack
- account/resource inventory
- already-tested boundaries
- specialist trigger detection
- child packet construction
- result merge and next-plan selection

The parent should not deep-test every vulnerability class itself.

## Specialist Trigger Examples

- `user_id`, `org_id`, `team_id`, `accountId`, object ownership hints:
  `/access-control` or `/idor`
- JWT, JWKS, `kid`, `jku`, `x5u`, claim-boundary behavior: `/jwt-auth`
- OAuth, SAML, account linking, password reset, MFA, invite flows: `/ato`
- upload plus render/download/preview/admin path: `/pfp`, `/stored-xss`,
  `/ssrf`, or `/access-control`
- report-to-admin, admin review, moderation, email/export render:
  `/stored-xss`, `/dom-xss`, browser/CDP, and callback watcher
- DOM sinks, router/hash/localStorage/postMessage/client templates:
  `/dom-xss`
- checkout, coupons, subscriptions, credits, invoices, refunds:
  `/payment-testing`
- 401/403/405 method or path boundary: `/error-triage`, `/403`,
  `/bypass`, `/headers`, or `/access-control`

## Child-Agent Packet

Each specialist receives only:

- exact objective and stop condition
- program, section, and full URLs
- relevant request shape, parameters, scripts, or map entries
- account/resource boundary and cleanup/destructible status
- selected skill and required policy skills
- relevant Hunter Memory attempts, constraints, and claims
- evidence standard for success

Do not pass raw cookies, bearer tokens, passwords, reset links, private headers,
API keys, broad proxy dumps, or unrelated app history.

## Output

Record parent-loop artifacts under:

`$HARNESS_SHARED_BASE/{program}/agent_shared/hunter-loop/<goal-or-section>/<run_id>/`

Recommended files:

- `TARGET_MEMORY.md` — durable map, auth recipe, constraints, and hypotheses
- `orchestrator-log.jsonl` — parent observations, decisions, dispatches
- `specialist-packets/*.json` — child handoffs
- `specialist-results/*.json` — child summaries to merge
- `benchmark.json` — optional lab scoring and blocker metadata
- `summary.md` — what changed in target memory and next action

Promote vulnerabilities only through the owning specialist's proof standard and
normal findings pipeline.

