---
name: hunter-loop
description: "Use when orchestrating a goal-driven bounty-hunter loop that maps an app, maintains target memory, and dispatches scoped specialist agents."
---

# Hunter Loop

Use this when Ryushe wants the agent to behave like a bounty hunter instead of
a scanner: map one app slice, interact with it, learn from each response, then
send focused specialists only when the app surface justifies it.

Hunter Loop is the parent orchestration skill. It does not replace `/xss`,
`/access-control`, `/idor`, `/jwt-auth`, `/ato`, `/payment-testing`,
`/deep-hunt`, `/live-map`, or `/hunter-memory`; it decides when to invoke them
and what scoped packet they should receive.

## Load Order

Read `general-security-testing-policy` first and follow its Cold-Start guidance (mirrored in `agents/index.md`):

1. **Scope Gate** — Read scope, account/resource context, and the active
   live-testing policy. Check `~/Shared/scopes/{program}/` first, then
   `~/Shared/bounty_recon/{program}/scope/`. If no scope exists, try
   `/pullscope`. If the program has no published scope, write `no scope` stub.
2. **Cold Surface Pass** — Read `$HARNESS_ROOT/prompts/hunter-loop-playbook.md`.
   Look at the app with fresh eyes. Browse, map endpoints, observe behavior.
   Avoid broad MapStore, ledger, or prior-lead reads until the agent has current observations.
3. **Fresh Observations** — Aim to identify 3-5 fresh surfaces, flows, parameters, roles,
   or assumptions from direct observation before following any existing leads.
4. **Memory Overlay** — Now query prior state as needed:
   - `/hunter-memory` summaries for the program or surface
   - `/live-map` application-map summary and handoff packets
   - `/url-ingest` stats/history for route and parameter review depth
   - raw or normalized recon artifacts for additional services, routes,
     parameters, features, roles, and technologies
   - `/map-store` for the URL, host, surface, and relevant vuln class
   Do not use prior confirmed findings, old report drafts, manual findings,
   high/medium vulnerability lists, MapStore `old-leads`, or `#do-not-retest`
   entries as target-selection input for new-finding goals. Use them only for
   dedupe, coverage, safety, rebound ideas, or explicitly requested
   revalidation/extension after a current surface exists.
5. Start or resume a target memory pack.
6. Map one app area at a time through live interaction, then dispatch
   specialists on evidence-backed triggers.

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

## Interactive Mapping Rule

Hunter Loop is not a passive crawler. Default to this cycle:

```text
map a little -> touch the app -> observe behavior -> write facts ->
form hypotheses -> test one boundary -> update the map -> repeat
```

Do not try to understand the whole application from overhead before the agent
has seen runtime behavior. Use browser/CDP, proxy, or a small controlled request
to learn how the selected surface actually behaves, then update MapStore with
stable facts.

Before dispatching a specialist, the parent packet should include the observed
behavior that justifies the handoff: reflection context, parser error,
callback evidence, auth boundary, object ID clue, sanitizer behavior, redirect
behavior, or another concrete signal.

## Attempts And Pressure State

Each specialist packet should name an attempts directory under the program
lane, for example:

```text
agent_shared/attempts/<vuln-class>/<surface>/<run-id>/
```

Use this pressure-state vocabulary when merging specialist results:

- `cold`: no signal yet; use small probes to learn whether the vector exists.
- `warm`: signal exists but no exploit; keep classifying defenses.
- `hot`: partial control or bypass clue; continue deliberate mutation.
- `exhausted`: representative families failed and the block is understood.

The parent may pivot automatically from `cold` or `exhausted`. For `warm` or
`hot`, prefer another discriminating probe on the same vector unless policy,
ownership, rate, or safety gates block it.

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
- attempts directory and required pressure-state fields
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
