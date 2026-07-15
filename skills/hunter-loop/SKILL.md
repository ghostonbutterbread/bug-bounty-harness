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

For a long-running multi-agent hunt, Hunter Loop may use Hermes Kanban as the
local orchestrator's durable work queue. External CLI agents keep their own
native session/run logs and publish only durable hunt outcomes into the
program's existing memory layers. MapStore remains structured app memory, not a
work queue or universal agent log. Load `references/hunter-kanban.md` before
creating a local Kanban team run. Use the packet and topology templates in
`templates/` rather than improvising broad `find a vulnerability` cards.

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

## Kanban Team Mode

Use team mode for a long-running program hunt, a hunt that must survive chat
turns/restarts, or work split between Ryushe, the parent agent, and multiple
workers. Do not use it merely to parallelize generic vulnerability-class
guessing. The Hunter Loop methodology is portable, but task state is not: Hermes
Kanban manages only work the local orchestrator owns. Remote CLI agents retain
their own session and task state rather than participating in a second shared
task database.

### Board Preflight

1. If the local orchestrator will dispatch Hermes workers, create or select one
   dedicated Kanban board for that program/workstream. Inspect `hermes kanban
   boards list`, `assignees`, and `stats` before dispatching. Do not mix
   unrelated programs on a board or synchronize the local SQLite board between
   machines.
2. For a remote CLI agent, issue a bounded Hunter Loop packet and let that
   runner keep its native session and log. Its return contract is stable
   MapStore facts/proposals, attempt artifact pointers, Bounty Notes handoffs
   when needed, and a concise result—not mirrored task state.
3. Confirm every assigned profile has the required tools and access to the
   relevant policy skills. Kanban workers are separate profiles/processes;
   policy inheritance must be explicit in each task packet, not assumed from
   the parent chat.
4. Create a scope-and-account gate as the first task. It records scope source,
   rate rules, owned account aliases, allowed actions, and auth-seed references
   without copying secrets. Block live tasks until that gate is complete.
5. Create a cold-surface mapping task before specialist tasks. Its required
   output is fresh current-run observations, not a MapStore lead summary.
6. Give every live card a bounded scope, lease, max runtime, stop condition,
   required policy chain, attempts path, and evidence standard. A worker may
   not expand its surface or start a new vulnerability lane without a new card.

### Board Roles

- **Parent / coordinator:** owns the app map, scope gate, task routing,
  duplication decisions, and result merge. It does not blindly test every lane.
- **Companion scout:** follows the current human-selected flow and returns
  fresh routes, parameters, roles, consumers, and trust boundaries.
- **Lane steward / specialist:** owns one evidence-backed surface family and
  adjacent questions across a bounded sequence of cards. Preserve the same
  worker's Hunter Memory and attempts context while a flow is warm/hot; do not
  respawn a generic "find a vulnerability" agent for every adjacent task.
- **Verifier:** independently reproduces a candidate; it does not inherit the
  originating worker's conclusion as proof.
- **Synthesizer / memory promoter:** merges results, evaluates chain ideas, and
  promotes stable app facts or gadgets to MapStore.

The Discord thread is the human control room. A local Kanban board is the
durable state machine for local workers only. Ryushe may work another thread
while the team runs; remote workers keep their native run logs and return
durable hunt outcomes, not ad hoc context dumps or mirrored board state.

### Surface Lenses And Steward Continuity

A selected target is a **surface plus a lens**, not necessarily a brand-new URL
or feature. A lane steward may revisit a known flow through a different bounded
lens when that exposes a real coverage or trust-boundary gap:

- identity, role, tenant, and object-ownership boundaries;
- lifecycle and state-transition behavior;
- browser/client/API consumer differences;
- parser, serializer, cache, and content-type boundaries;
- integration, callback, import/export, and downstream-consumer behavior;
- technology/dependency/configuration behavior; or
- offline source/JavaScript analysis connected to the observed live flow.

Prefer assigning the next adjacent, same-surface task to the existing steward
while its pressure state is warm/hot. Split work only for independently
testable, evidence-backed questions or a distinct offline slice. A verifier is
always a fresh independent worker. Record the surface, lens, prior steward
artifact pointer, and reason for continuation or rotation in each follow-up
packet.

### Authorized Training-Lab Completion Mode

For an explicitly authorized disposable training lab, a "complete" goal means
follow the evidence-backed chain to the lab's objective or an evidence-bounded
stop—not merely prove the first primitive. The scope gate must state whether
the lab objective, disposable account creation, and lab-local state changes are
allowed. Do not infer those permissions from a generic live-target policy.

- Give the worker a trusted objective/acceptance criterion in its task packet
  when Ryushe authorizes it. The task may still forbid solution pages when the
  purpose is a blind benchmark, but it must not make the objective unknowable.
- When a hot output-sink signal occurs, map the whole adjacent chain before
  declaring "no action boundary": direct echo versus model-mediated output;
  model-visible indirect sources; retrieval/function paths; the victim/browser
  context; and the owned or lab-local action that demonstrates impact.
- Use an action ladder: harmless sink proof -> controlled owned/disposable
  action proof -> explicitly authorized lab-objective action. A primitive
  alone is not completion when the stated benchmark is a chain. Once the next
  owned/disposable edge is evidence-backed and permitted, it is the default
  continuation target—not a risky escalation to avoid. The steward must either
  test it, record the specific scope/ownership/stability blocker, or hand the
  same warm/hot chain to its next continuity card.
- In a real program, stop before a non-owned or third-party state change even
  if the chain is otherwise proven. In a training lab, such a fixture action is
  allowed only when the scope gate names the lab objective and the user has
  approved it.

When the program scope changes—for example, a new PortSwigger Academy lab or a
different host—reset application-specific MapStore assumptions. Preserve only
methodology-level lessons in the appropriate training/reference material; do
not carry routes, objects, auth behavior, or apparent gadgets from one lab/app
into another as app facts.

## Cross-Orchestrator Concurrency

Multiple independent agents may hunt the same program, but they do not
automatically know what each other is doing. Before a long-lived goal run or a
local Kanban team starts, consult the program's small active-run presence
directory when it exists:

```text
agent_shared/active-runs/<run-id>.md
```

This is intentionally not a shared to-do list, worker transcript, or historical
ledger. It is a short-lived air-traffic-control record: owner, runner type,
current flow/surface lease, testing mode, start/checkpoint/expiry time, and a
sanitized contact/handoff pointer. Use
`templates/active-run-presence.md` as the record shape.

- A local Kanban team writes one aggregate presence record for its active
  surface leases; it does not mirror every internal card.
- An external CLI goal run writes its own presence record and retains its own
  detailed session/run log.
- Agents may work concurrently on distinct flows or offline artifacts. Do not
  concurrently own the same live flow or exact specialist question unless the
  coordinator explicitly assigns complementary work.
- Presence records expire or are removed when a run ends. They are not promoted
  into MapStore.
- A coordinator resolves overlap by changing a surface lease, not by creating a
  second universal queue.

MapStore serializes its own writes with a local lock and atomic write path when
agents share the same mounted store. That prevents file corruption, not
duplicate testing or cross-machine synchronization races. Do not rely on an
eventually synchronized copy as a concurrency lock; remote agents should return
proposals/artifact pointers for a coordinator to merge when shared locking is
not trustworthy.

The scope/rate gate applies across all active agents. Treat the aggregate
program traffic, owned-account mutation, and callback volume as one campaign,
not as independent per-agent allowances.

### Freshness And Memory Guard

For a new-finding goal, a worker must attach at least one fresh current-run
observation before it may create a specialist follow-up, label a lead
meaningful, or use historical material as a target-selection reason. Valid
fresh evidence includes a newly observed route/consumer, response differential,
role or object boundary, parser/render behavior, or a reproducible browser/API
state.

MapStore reads are targeted `app-facts`, `dedupe`, or `coverage` queries after
the current surface exists. Do not make `old-leads`, past findings, or broad
MapStore ingestion the opening move. If two consecutive targets were chosen
mainly from old state, or roughly 30-45 minutes pass without a fresh
observation, pause historical retrieval and require three fresh observations
before another old-lead pivot.

Workers write exact probe history in their attempts directory and may propose
MapStore entries in their result. The coordinator or designated memory promoter
dedupes and writes shared durable conclusions. Do not bulk-write speculative,
duplicated, or raw run state into MapStore.

### Task Lifecycle

1. Scope/account gate -> cold-surface mapping -> structurally plausible or
   evidence-backed specialist cards.
2. Each specialist returns a structured result plus a prioritized, non-capped
   hypothesis ledger. It may request the best bounded follow-up card, but it
   does not silently broaden its live mission or discard viable deferred angles.
3. A verifier card is required before candidate promotion. For stochastic AI
   behavior, the verifier must preserve the candidate's semantic trigger and
   acceptance predicate (for example, indirect content -> model retrieval ->
   role-separated output), while using a clean profile/operator and independently
   generated proof. Do not falsely "verify" by changing both the content path
   and the discriminator at once; that produces an inconclusive experiment, not
   a refutation.
4. Create a synthesis card whenever multiple specialist cards could expose
   compatible primitives. Link it as dependent on those cards so chain review
   cannot be skipped.
5. The synthesizer promotes stable facts to MapStore, hunt narrative to Bounty
   Notes, and verbose evidence to the correct artifact lane. It writes the next
   selected surface or explicit stop reason to the board.

Use `hermes kanban swarm` only after concrete worker cards exist. Its worker ->
verifier -> synthesizer graph matches this lifecycle, but it does not replace
the scope gate or fresh-observation requirement.

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
form and retain hypotheses -> test one discriminating boundary -> update the map
-> repeat
```

Do not try to understand the whole application from overhead before the agent
has seen runtime behavior. Use browser/CDP, proxy, or a small controlled request
to learn how the selected surface actually behaves, then update MapStore with
stable facts.

Before dispatching a specialist, the parent packet should include the fresh
observation or structural plausibility that justifies the handoff: controllable
input reaching a class-shaped field/consumer, stored content with a later
consumer, reflection context, parser error, callback evidence, auth boundary,
object ID clue, sanitizer behavior, redirect behavior, or another concrete
signal. A positive vulnerability signal is not required before a bounded
signal-generation card.

## Hypothesis Breadth And Novel Lanes

Hunter Loop does not cap the number of evidence-grounded hypotheses a steward
or parent may retain. Preserve distinct viable angles in Hunter Memory or the
task artifact as `candidate`, `active`, `deferred`, `combined`, `disproved`, or
`blocked`; do not lose an angle simply because it is not the next live test.

Live action remains bounded by scope, ownership, rate, safety, and the owned
card objective. Choose the next experiment for information gain and impact fit,
not because the hypothesis list is short. A worker must state its active chain,
the minimum sufficient discriminating test, expected interpretations, and wake
conditions for deferred hypotheses.

When no narrow vulnerability skill fits a structurally plausible or warm/hot
surface, route the worker through `hypothesis-expansion-policy` together with
the general/live-testing policies. The worker may pursue the bounded question
and propose a sanitized skill seed for a reusable pattern; it must not treat a
missing skill as either a stop condition or permission to exceed the safety
gate.

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
- card/run ID, lease owner, and a statement of what this worker must not test

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

For team mode, also record:

- `kanban-board.md` — local board slug, task IDs, role/profile assignments, and
  safe human check-in commands, when local Kanban is used
- `mapstore-proposals/` — worker proposals pending synthesis, if the worker did
  not safely promote a stable fact itself
- `handoffs/` — concise takeover packets for blocked tasks or human steering

Promote vulnerabilities only through the owning specialist's proof standard and
normal findings pipeline.
