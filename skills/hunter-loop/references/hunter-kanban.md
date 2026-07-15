# Hunter Loop Kanban Reference

Use this reference when a local Hermes orchestrator needs durable, multi-agent
coordination. It turns one program hunt into a bounded task graph without
treating MapStore as a queue of old leads.

## Boundary: Local Kanban, Independent Remote Runs

Hermes Kanban is a local-host board backed by `~/.hermes/kanban.db`. Use it for
Hermes profiles that the local orchestrator dispatches. Do not copy, sync, or
make remote agents write that SQLite database.

Codex, Claude Code, OpenCode, or another remote CLI agent can follow the same
Hunter Loop methodology without joining the local board. Give it a bounded task
packet, let it keep its own native transcript/log and local goal/session state,
and accept only its durable hunt outputs:

- stable MapStore fact or proposal, scoped to a concrete URL/surface/app fact
- attempts artifact pointer and concise pressure-state result
- Bounty Notes handoff when a decision, blocker, or next-agent rationale matters
- reusable script/artifact manifest when relevant

Do not add a second universal task database, mirror remote to-dos into Kanban,
or turn MapStore into a chronological event log. The local board describes what
the local orchestrator owns; the program stores describe what has been learned
about the application.

## Concurrent Agents Outside One Board

Kanban coordinates its own local workers. A remote Codex/Claude run is not
visible to that board automatically, and two independent "find a vulnerability"
goals can otherwise choose the same flow at the same time.

Use the program's short-lived `agent_shared/active-runs/` presence directory as
the only shared concurrency signal. It is an expiring surface lease, not a
universal to-do list or run log. Before starting or pivoting a long task:

1. Read active presence records and select a distinct flow, surface, or offline
   artifact slice.
2. Write one presence record using `templates/active-run-presence.md`.
3. Refresh it at meaningful checkpoints; remove or mark it finished on exit.
4. If another worker owns the same exact live flow/question, ask the
   coordinator to split complementary work or choose a different surface.

MapStore's local write lock protects its files from concurrent writers on the
same mounted filesystem. It is not a distributed scheduler and does not prevent
two workers from testing the same behavior before either writes a result.

The scope/rate budget is program-wide. A coordinator must account for active
workers collectively; independent agents do not each receive a separate traffic
allowance.

## Preconditions

Before creating live tasks:

1. Verify the program scope, rules, request/rate constraints, and owned account
   context using `general-security-testing-policy` and its narrower policies.
2. Choose one dedicated board per program/workstream. Inspect the existing board
   and assignees before adding work; do not mix programs on the default board by
   accident.
3. Confirm the assigned Hermes profiles can load the necessary policy and hunt
   skills. Profiles are isolated: pass the required policy chain in every card
   and do not assume a worker inherited the parent thread's context.
4. Keep raw session material in approved restricted auth-seed locations only.
   Cards, comments, MapStore, Shared artifacts, and task logs contain aliases,
   references, and sanitized request shapes—not values.

Use `hermes kanban <subcommand> --help` to verify the installed command shape
before changing a board. Useful inspection commands are `boards list`,
`assignees`, `list`, `show`, `stats`, `runs`, `log`, and `tail`.

## Roles

| Role | Owns | Must not do |
| --- | --- | --- |
| Coordinator | scope gate, surface selection, leases, dependency graph, dedupe, result merge | deep-test every lane or accept an unverified finding |
| Companion scout | fresh observations in the human-selected flow | choose old leads as targets or broaden into unrelated lanes |
| Lane steward / specialist | one surface family plus adjacent structurally plausible or evidence-backed questions; retain viable hypotheses while warm/hot | silently expand live scope, discard useful active context, or treat speculation as confirmation |
| Verifier | independent reproduction with the same safety boundary | inherit the original worker's conclusion as evidence |
| Synthesizer / memory promoter | chain review, durable-memory promotion, next-plan selection | turn raw attempts or speculative notes into MapStore facts |

A Discord thread is the human control room. The board is the source of task
state. The coordinator writes concise board events rather than pasting broad
proxy history into chat or worker prompts.

## Surface Lenses And Context Continuity

Do not define a surface only as a new endpoint. A worker can revisit a known
flow through a new lens: identity/tenant/object authority, lifecycle,
client-vs-API consumer behavior, parsing/serialization/cache, integration and
downstream consumers, technology/configuration, or connected offline source
analysis.

Keep adjacent cards for the same warm/hot surface with one lane steward and
pass its attempts/Hunter Memory pointer forward. Split only independently
testable questions; use a fresh worker for verification. Every continuation or
lens rotation must state the prior evidence, the new lens, and the reason the
question is not a duplicate retest.

When a board changes to a different application/lab scope, reset app-specific
MapStore assumptions. Training/methodology lessons may transfer, but routes,
objects, roles, and gadgets from one application must not be treated as facts
about another.

## Recommended Graph

```text
scope-and-account gate
        |
        v
cold-surface map / companion scout
        |
        +--> specialist: one evidence-backed question
        +--> specialist: independent adjacent question
                 \               /
                  v             v
                    verifier(s)
                        |
                        v
              synthesis + memory promotion
                        |
                        v
              next selected surface or stop
```

The board may use Hermes's worker -> verifier -> synthesizer swarm shape once
concrete worker cards exist. Never use a swarm to bypass the scope gate or to
fan out generic `find vulnerabilities` prompts.

## Card Rules

Every live card must contain:

- a single objective and owned section/URLs
- the concrete fresh observation or structural plausibility that justified it
- scope/rate/account policy chain and an account alias or approved seed
  reference, never raw credentials
- explicit out-of-scope actions and a stop condition
- attempts/artifact path, evidence standard, and maximum runtime
- freshness status and the narrow MapStore intent, if one is needed
- result requirements: verdict, pressure state, evidence pointer, reusable
  constraints, active/deferred hypothesis ledger, proposed memory changes, and
  one recommended next step

Use `templates/kanban-task-packet.md` verbatim or adapt it without dropping the
safety, freshness, and stop fields.

## Memory Promotion

Keep the layers separate:

- **Attempts:** exact payload/probe history and raw/verbose evidence under the
  program run artifact path.
- **Hunter Memory:** active hypothesis state, observations, and learned
  boundaries for this run/surface.
- **MapStore:** stable URL/surface/app facts, representative negative outcomes,
  defenses, and sanitized artifact pointers.
- **Bounty Notes:** chronology, decisions, handoffs, blockers, and why a path
  was selected or paused.
- **Kanban:** task state, dependencies, ownership, comments, and run results.

Workers propose MapStore updates; the synthesizer/coordinator dedupes and
promotes them. A worker may write an immediate MapStore fact only when it is
stable, narrowly scoped, and not speculative. Never bulk ingest historical
entries or add one MapStore entry per transient attempt.

## Freshness Circuit Breaker

For new-finding work, pause and return the card for a cold-surface pass when:

- the task has no fresh observation tied to the current run;
- two target choices were driven mainly by historical leads; or
- roughly 30–45 minutes passed without a new route, behavior differential,
  consumer, trust boundary, object boundary, parser/render observation, or
  comparable signal.

The recovery condition is three fresh current observations from the selected
app/session, then a targeted `app-facts`, `dedupe`, or `coverage` lookup if
needed. `old-leads` stays reserved for explicit retest/repass/triage work.

## Human Check-ins

A coordinator should report only material events:

- scope/account gate completed or blocked
- a fresh observation materially changed the plan
- a card needs human input, approved credentials, CAPTCHA help, or a policy
  decision
- a candidate is ready for independent verification
- the synthesis card selected the next surface or recorded an explicit stop

A human can steer with short directives: focus a flow, pause a lane, ask for a
summary, choose an adjacent surface, or block a task. The coordinator records
that decision in the board and target narrative before dispatching more work.
