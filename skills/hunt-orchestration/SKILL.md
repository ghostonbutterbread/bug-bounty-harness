---
name: hunt-orchestration
description: Use when an agent is asked to hunt, examine, or explore a security target and must decide whether to remain a solo hunter or launch bounded research, mapper, verifier, or synthesis sidecars.
---

# Hunt Orchestration

## Purpose

Keep the primary hunter autonomous and context-light while using sidecars only
for real coordination advantages. This is an orchestration discipline, not a
requirement to turn every target review into a multi-agent team.

`hunt-orchestration-policy` owns sidecar admission and policy packet boundaries;
this BBH skill owns mapped-program reorientation, transport triage, evidence
stores, and a concrete operator handoff. It does not replace that policy or
the `hunter-loop` cadence.

Load the security-policy router and scope/account rules first. The primary agent
continues to own the target map, live decision-making, rate budget, and final
merge of results.

## Mapped-Program Reorientation

When the operator asks how to continue an already-mapped program, do not answer
from a generic vulnerability taxonomy or restart broad reconnaissance. First
retrieve the program policy and bounded MapStore `app-facts` plus `coverage`
views; then read the most recent focused technical handoff if one exists.

Synthesize those sources into a short ranked queue of stack-grounded primitives.
For each, name the observed stack/consumer fact, the narrow security question,
the smallest safe discriminator, and its stop condition. Separate a genuine
mapping gap from a testing bottleneck: a very large URL or host corpus is not by
itself a reason to collect more breadth. Carry forward any rate, owned-account,
sensitive-surface, public-interaction, and cross-brand dedup rules that alter
which lane should be first.

## Default Loop: Solo Primary Hunter

Start solo for an ordinary request to inspect, look at, or hunt an application:

```text
scope/account gate
-> cold current-surface pass
-> fresh observations
-> targeted MapStore facts, hypotheses, and coverage lookup
-> one discriminating live test
-> continue, pivot, prove an owned impact edge, or close with evidence
```

Keep the primary context to its current flow, active hypothesis, concrete
MapStore slice, and compact sidecar decisions. Do not preload whole source
trees, broad proxy histories, old findings, or campaign transcripts.

Stay solo while the current flow is warm/hot, stateful, or has a direct next
discriminator. Do not launch agents merely to generate more payload variants or
read the same endpoint independently.

## Transport and Intermediary Failure Gate

Before treating a response as application evidence, classify whether it came
from the target or from an active proxy, browser, CDN, or other intermediary. A
listening proxy port is not proof that it can forward the selected scoped flow.

If a bounded owned request returns a 5xx, timeout, or reset with an intermediary
marker, make at most one minimal reproduction when the live-status policy allows
it. If it is identical or still intermediary-generated, stop target requests
**through that affected transport path**: payload variants on the same broken
path would repeat a transport failure. Do not infer all scoped routes are down.
An independently healthy transport lane may continue only after its own
scope, rate, and transport preflight. Record the affected path as a **transport
blocker**, not a target negative or vulnerability candidate.

Do not dispatch a mapper, verifier, or parallel hunter through the same broken
path. A sidecar is appropriate only after transport is restored, or for a
separate offline diagnostic decision that needs no further target requests;
work on independently healthy lanes follows the usual sidecar and rate gates.
Persist only sanitized fingerprints (status, response size/hash, intermediary
marker, proxy lane, request count, and restart condition) in restricted run
artifacts, with a concise handoff/blocker pointer in `bounty-notes`—never
cookies, identity-header values, or raw private response content. Add a MapStore
entry only for separately verified target behavior, not an intermediary failure.

## Event-Driven Sidecars

First distinguish a **reset signal** from a delegation trigger. When work is
driven by old notes rather than a fresh target observation, or a lane turns
cold or blocked, return to the current application before delegating. Do not
use a sidecar merely to avoid that reset.

Create a sidecar only when a post-reset current observation gives it a concrete
coordination advantage. Good triggers include:

- a current SDK, API schema, protocol, provider, webview bridge, parser, or
  downstream consumer determines the next live test;
- a distinct route, consumer, role, state transition, or trust boundary was
  independently observed;
- the primary has a hot chain worth preserving but campaign coverage needs fresh
  options;
- a candidate needs clean independent reproduction; or
- separate source analysis and live testing can proceed without competing for
  the same session, rate budget, or owned resource.

Do not spawn when the second worker would compete for the same rate budget,
owned resource, stateful session, or merely repeat the primary's work.

### Knowledge Sidecar

Use for a single bounded decision question about a source/documentation target.
Examples: what operations an SDK authorizes; whether a client-side check has a
server-side counterpart; which signer, callback, parser, or bridge consumes a
value; or which configuration becomes a security boundary.

The packet must name:

- the triggering current observation and artifact pointer;
- one decision question;
- allowed source/documentation/artifact scope;
- excluded work, especially unrelated live testing;
- stop condition; and
- the exact result needed by the primary hunter.

The result returns a decision-ready memo: source-backed capabilities, trust
boundaries, consumers, documentation/source pointers, source-only MapStore
proposals, unresolved live-only questions, and the best next discriminator.
Stop when the decision is answered or remaining uncertainty requires live proof.

### Mapping Sidecar

Use when the primary should continue a warm/hot chain but needs breadth support.
Map an adjacent or distinct bounded surface for fresh routes, consumers, roles,
state transitions, header/proxy behavior, integrations, and coverage gaps. Do
not duplicate the primary exploit attempt or turn mapping into unbounded
crawling.

### Independent Verifier

Use only for a credible candidate. Give the verifier a minimal owned fixture,
source type, triggering workflow, role/context, expected consumer, and exact
semantic acceptance predicate. It must use a clean profile/operator and an
independently constructed safe proof, not the originating hunter's narrative.
A materially changed predicate is inconclusive—not a refutation. Return
reproduced, not reproduced, inconclusive, or blocked with an artifact pointer
and next proof/closure recommendation.

### Synthesis

When broad, multi-surface, or parallel specialist tasks are created, create a
blocked/dependent synthesis checkpoint with them. Run it after their results are
available to assess confirmed primitives and gadgets for compatible chains. It
evaluates evidenced compatibility and impact paths; it does not invent chains
from unrelated historical notes.

## Sidecar Safety and Context Contract

Every child receives only:

- objective, stop condition, and run/lease identity;
- scope, rate, policy, and owned-account/resource references;
- one triggering observation and a narrow surface or decision lens;
- allowed evidence sources and explicit exclusions;
- artifact/documentation location; and
- structured return fields.

Never pass raw cookies, bearer tokens, CSRF values, reset links, API keys, broad
proxy exports, unrelated findings, or full campaign context. Pass an account
alias or secret-safe seed reference only if the task needs it.

Source analysis may create concise documentation with source/revision pointers,
but source-derived claims remain **source-confirmed, live-unverified** until an
owned live test proves production behavior. Store reusable facts, tested
negatives, hypotheses, and leads with distinct types/evidence basis; retain exact
payload/request history in restricted attempt artifacts.

## Lead Promotion and Continuation

A **lead** is a hypothesis with enough observed backing to become a shared,
lifecycle-managed work item. Keep untested branches, owner lease, and wake
conditions private in the Hypothesis Ledger. When a branch has a durable
observed fact plus one bounded unresolved security question, create or update
its sanitized public projection via `leads`, tagged `lead` and the relevant
vulnerability class in MapStore. Link a hypothesis ID only as a non-secret pointer; do not publish another
live agent's private branches.

Update the same projection as it strengthens, acquires a named prerequisite,
becomes stale/defended, is archived with an evidence-backed wake condition, or
is promoted to a finding. Do not silently abandon warm/hot branches. A blocker
pauses only that lead: continue independent work and report a compact operator
unblock card only when the smallest legitimate action is needed (selected owned
account/role, fixture, browser recovery, artifact, scope decision, or cooldown).
A persistent challenge is a classification and handoff condition, not an evasion
campaign.

## Off-Goal Discovery Preservation

While pursuing a named vulnerability goal, preserve any distinct discovery even
when it does not change the active chain: reusable observed facts, gadgets, and
material residuals belong in MapStore; untested private continuations belong in
Hypothesis Ledger; a durable fact plus one bounded unresolved security question
becomes a sanitized Lead; reportable proof and impact enter Findings; and exact
deliberate probes remain in Attempts. Record non-secret pointers rather than
copying payloads or private rationale. Continue the active goal unless the new
discovery changes scope, safety, or the impact decision.

## Coordinator pressure on a promising surface

In a multi-agent hunt, keep the current steward on a plausible warm/hot flow
while distinct security lenses remain. The coordinator may challenge shallow
closure with the question “what distinct mechanism remains?”; that pressure is
motivation, not an observed fact or finding. At a checkpoint ask for attempted
lenses, discriminating observations, remaining mechanisms, and the next bounded
authorized test. Do not repeat equivalent probes or impose a fixed nudge/payload
count as a technical closure rule. Release the surface on evidence-backed
exhaustion, an actual prerequisite blocker, or policy/scope/rate constraint.
Pass a credible candidate to a clean independent verifier without presenting
the coordinator's confidence as proof.

## Checkpoint and Pivot

At a natural checkpoint, record three choices:

```text
continue: next discriminator on the current chain
adjacent: a different lens on the current flow
novel: independently observed surface or coverage gap
```

Choose intentionally. This prevents tunnel vision without forcing the primary to
abandon a high-information chain.

## Operator Handoff Queue

When the operator says that agent results leave them unsure what to do next,
turn the current map into a **one-hot-chain queue**, not another broad hunt.
Rank only a few evidenced lanes. Each queue card must state: impact hypothesis,
observed basis, one exact unknown, smallest permitted discriminator, prerequisite
or stop condition, and the return decision.

Use this control loop:

```text
one primary chain -> bounded agent result -> Continue | Verify | Pivot
```

- **Continue:** the result strengthened the same chain and exposes a direct next
discriminator; keep the browser/session owner and rate budget with the primary.
- **Verify:** a credible candidate now has an independently testable semantic
predicate; assign a clean owned-profile verifier rather than another explorer.
- **Pivot:** the prerequisite or required chain link failed; explicitly select
the next ranked, independent lane instead of asking a new agent for generic
ideas.

A useful sidecar return therefore names its exact `Continue | Verify | Pivot`
recommendation and the evidence pointer supporting it. This preserves operator
agency while preventing idle handoffs and duplicate exploratory work.

## Long Goal Mode

For durable, multi-surface work, use a portfolio only when evidence warrants it:

```text
primary hunter: strongest live signal and continuity
mapper: fresh coverage and alternate surfaces
knowledge sidecar: SDK/API/source decision bottleneck
verifier: independent candidate reproduction
synthesizer: confirmed-primitive chain checkpoint
```

Roles rotate or disappear as evidence changes. A strong solo hunter is better
than several generic parallel hunters. When the selected flow needs authentication,
start with one approved owned program account; acquire another on demand for
cross-principal/role tests or a session constraint, not as a universal hunt-start
gate. Public or anonymous in-scope work does not need an account. The browser
provisioner owns exact leases and program-specific same-account concurrency.
On unexpected logout, preserve non-secret lease, timing, and authentication-check
evidence to distinguish session collision from expiry before changing that
program rule; never silently substitute another identity. Container isolation
is a separate boundary decision, not a prerequisite for this loop.

## Pitfalls

- **Parallelizing guesses:** never split equivalent payload spraying across agents.
- **Breaking hot-chain continuity:** mapper work should support, not interrupt,
  the primary's live sequence.
- **Unbounded research:** a sidecar studies one decision question, not an entire
  ecosystem.
- **Context dumping:** return conclusions and pointers, not full transcripts.
- **Source-as-proof:** source behavior does not establish production deployment,
  backend authorization, or feature-flag behavior.
- **Scope expansion:** a new host, live flow, vulnerability lane, or destructive
  action needs a new scoped packet and policy decision.

## Completion Check

Before closing an orchestration checkpoint, verify that the primary has a next
discriminator, concrete blocker, or evidence-backed closure; each sidecar had a
specific advantage and bounded result; durable knowledge is promoted or deferred
with pointers; and no duplicate work, secret transfer, scope drift, or shared
rate-budget conflict occurred.
