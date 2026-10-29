---
name: bug-goals
description: Route an explicitly invoked /goal bug-bounty objective into the right hunt mode, reasoning cadence, retrieval choices, and existing skills without changing normal agent use.
---

# Bug Goals

## Trigger and boundary

Use this skill **only** when the user explicitly starts a bug-bounty goal with
`/goal` or an equivalent explicit goal-run invocation. Do not load it for normal
chat, ordinary security questions, one-off investigation, or background work.

This is a Bug Bounty Harness skill. Keep its canonical source under
`skills/bug-goals/`; do not place goal-routing,
research-escalation, or hunt orchestration in the AI Policies repository. AI
Policies may define safety boundaries and the meanings of knowledge sources, but
must not own bug-bounty goal workflow.

This skill is a goal router. It does not replace `general-security-testing-policy`,
`live-testing-policy`, `hunter-loop`, `map-store`, or specialist skills. Loading
`bug-goals` or reading its generated plan does not load or apply the skills the
route names. Load each applicable routed skill before acting on the part of the
goal it governs; load conditional specialist skills when their trigger applies
rather than preloading every possible class. Use the BBH helper named
`scripts/goal_router.py`, not `goal.py`, to avoid ambiguity with Hermes, Codex,
and Claude standing-goal commands.

Use the BBH helper to produce an auditable plan before the first target action:

```bash

bbh scripts/goal_router.py plan --program <program> --objective "<goal>" \
  [--url "<url>"] [--class <vulnerability-class>]
```

Use `init` only after choosing the approved run-artifact directory. It writes
routing state only; durable target truth belongs in MapStore.
For a coordinated run, resolve the worker storage first and bind the goal run
with `bbh scripts/goal_router.py init --program <program> --objective '<goal>'
--run-dir <approved-run-dir> --family <family> --lane <lane>` (add `--class` for a
focused class). The checkpoint refuses another family/lane. Old unbound run
artifacts remain readable but should not be used for new worker dispatch.
`init` will not replace an existing run; resume it instead of erasing its
checkpoint history or rebinding its lane.

## Goal-only Coverage checkpoint

The **goal parent** owns a continuation decision after mapping a current path,
at a meaningful pivot or worker handoff, and before a negative stop. This is
not a per-payload ritual or a condition on normal interactive work. In a solo
goal the same agent is the parent; with Hunter Loop/Bunny workers, the parent
reconciles their scoped results. In collaborative Bunny, the worker writes and
reads back its own evidenced Attempts, MapStore observations and scoped Coverage
assessment; the parent reads the IDs and reconciles open siblings rather than
transcribing a second copy. Load `/coverage` before using its statuses.

Read the current class/lane Coverage `brief` (page when needed), then inspect
source-attributed inventory relevant to the decision: scoped services/hosts,
routes and named inputs, runtime/UI and authorized proxy maps, JS/API paths, or
native entry points as applicable. Use Recon Bus or the owning mapper for a
named corpus; no file such as `params.txt` or `urls.txt` is mandatory. An empty
or thin Coverage ledger means mapping may be missing, not that the class is
clean. Register only relevant observed questions with `/coverage` `discover`;
do not bulk-promote URLs into class assessments or copy probes into Coverage.

Choose **deepen** the current chain, **explore** a different observed path,
**map** another feature/service, **unblock** a concrete prerequisite, or a
**bounded-stop** with residual unknowns and a wake condition. A blocked
consumer, stale review, or unassessed sibling remains open until evidence
resolves it. Specialist skills decide the next discriminator, including defense
or multi-step research; Coverage does not prescribe a payload or stop quota.
Preserve strong warm/hot work rather than interrupting it to satisfy breadth.

Record the parent decision in the explicit run artifact, after `init`:

```bash
bbh scripts/goal_router.py checkpoint --run-dir <approved-run-dir> \
  --family <family> --lane <lane> \
  --decision <deepen|explore|map|unblock|bounded-stop> \
  --reason '<evidence-grounded short reason>' --next-step '<next action or wake condition>' \
  [--class <class-for-broad-goal-continuation>] \
  [--inventory-ref <sanitized-source-ref>] [--remaining '<specific unknown>']
```

It reads up to ten mapped questions with counts and `next_offset`, atomically
records a run-local receipt in `goal-state.json`'s checkpoint history and last
decision, and never assesses Coverage or contacts the target. `missing` means
no ledger; `empty` means no registered class questions; `no_matching_questions`
means the ledger has other questions but none for this class/host filter.
Negative `bounded-stop` cannot filter away another host, or a class in a broad
goal; omit `--class` for a broad-goal bounded stop. Follow `next_offset` with
Coverage `brief` before claiming the mapped frontier was reconciled. Name the
source inventory checked; a source pointer is not proof that every row was
reviewed. `bounded-stop` is a **paused, evidence-bounded run**, never success
for a “find vulnerability” objective. Only independently verified fulfillment
of the stated objective merits goal completion. This BBH helper does not
intercept the external goal runner's completion operation.

## Before calling a hunt goal done

This is an explicit behavioral requirement for a vulnerability-hunt `/goal`.
Agents were treating a finished current path as a finished objective, so a
stop never asked whether other surface would still serve the goal. The
question is guidance for the next skill, not a sweep and not a second checklist.

Before treating a vulnerability-hunt goal as done, ask whether unexamined surface would still move this objective.
That question also applies before a negative exhaustion stop. A strong current
signal still comes first. Do not leave a warm or hot chain to satisfy the question.

Answer by loading the skill that owns the missing question:

- Another consumer, API operation, parameter, or JavaScript corpus might still
  serve the goal → `surface-expansion`.
- The runtime map is thin or an owned flow was never exercised → `live-map`.
- An observed component could change the next decision → `technology-research`.
- A filter, parser, or access control is why the current path stopped →
  `bypass`, or `waf` when that skill's trigger applies. That is the creative
  question: a distinct mechanism, not a second idea list.
- An auth or role state the goal could depend on is untested → `access-control`.
  A client or UI claim whose server enforcement is unproven → `assumption-testing`.

If none of those questions would change the next action, say why. Only verified
fulfillment completes the goal; otherwise record a bounded stop with the residual
and wake condition. Do not reopen a locally exhausted lane without a new wake
condition.

The goal router's completion contract carries this question for broad, focused,
and continuation hunts. Technology-review and revalidation goals do not get it:
a technology question stays on the observed component, and a retest stays on the
prior issue.

## Goal modes

### Broad program

Trigger: generic objectives such as “find a vulnerability.”

Load Hunter Loop as the parent cadence and `hunt-orchestration-policy` to
consider whether a bounded mapper, knowledge, or verifier sidecar offers a
concrete coordination advantage. It is optional and never requires delegation.
Begin with scope, enough cold recon/live mapping to name meaningful current
surfaces, fresh observations, and a chosen surface plus lens. Do not start from
broad historical lead retrieval or assume a vulnerability class before current
evidence justifies one. MapStore is available for a later targeted overlay, but
do not query it until a concrete current surface and decision question exist.

Mapping is orientation, not a prerequisite for exhaustive coverage. A strong
current signal may be pursued immediately and as deeply as justified; incomplete
mapping is not a reason to interrupt a warm/hot chain. Use the coordination
overlay only when it provides a concrete advantage; it never requires children.

Before a broad negative or exhaustion conclusion, ask: **“Is there more to
map?”** Reconcile unvisited or unexercised normal UI/browser behavior, relevant
client/JS capabilities, authorized task-MITM feature traffic, available
role/auth states, and material consumer families. Record unavailable UI, missing
access, failed auth recovery, or absent authorized MITM traffic as coverage gaps,
not evidence of exhaustion. This reconciliation does not reopen a locally
exhausted lane without a new wake condition. When an unvisited family might
still move the goal, choose the owning skill in **Before calling a hunt goal
done** rather than treating the family as exhaustion.

### Focused surface

Trigger: a named URL, feature, workflow, or vulnerability class.

Map the normal workflow and exact input → transformation → consumer path. Use
targeted MapStore facts only after a concrete current surface/question exists,
then load a relevant specialist skill. Do not launch broad recon or a
multi-surface campaign unless the evidence requires it.

### Error Mapping

Trigger: the user explicitly asks to hunt for errors, map error behavior, or farm signal from error responses on a target.

Load `error-mapper` for the bounded comparison probe set and default character families. Load `request-exploration` for systematic parameter, type, header, and body mutation beyond the default set. Load `error-intelligence` for signal triage, tagging, and Error Store routing.

Goal: trigger class-appropriate errors across the application — parameter mutations, type mismatches, malformed values, missing fields, parser boundaries, path characters, encoding edge cases — and capture meaningful differentials. Each error response teaches something: framework names, internal paths, stack traces, validation order, parser boundaries, upstream consumers.

Triage errors by signal and class in your analysis; these are not Error Store fields or query filters. Record supported layer/channel and route high-signal errors (stack traces, SQL/database errors, internal path leaks, debug disclosures) to the relevant specialist skill or Finding Capture. Map differentials through `error-intelligence`. Preserve untested continuations in the Hypothesis Ledger; push reusable facts to MapStore.

### Technology review

Trigger: understanding an implementation, library, framework, parser, sanitizer,
render path, or source/runtime boundary.

Identify the exact version/configuration/call sites and compare source/runtime
behavior with the relevant consumer. Official documentation and source analysis
may occur immediately when technology understanding is the missing prerequisite.

### Continuation

Trigger: a warm/hot lead, a roadblock, or an explicit resume request.

Read Hunter Memory/attempt context; restate the active mechanism and missing chain
edge. Preserve continuity and choose a meaningfully distinct next discriminator.

### Revalidation

Trigger: retest, repass, old issue, or prior lead review.

Historical target material is primary input, but establish a fresh baseline and
record current behavior separately from prior observations.

## Surface Synthesis

After enough current target evidence exists to reason, create internal hypotheses
before broad external retrieval. This is not a mandatory delay when an unfamiliar
technology requires basic comprehension.

Use these lenses:

- **Implementation:** source, transformation, parser, sanitizer, serializer,
  validator, runtime, and downstream consumer.
- **Trust boundary:** attacker/victim, role, tenant, client/server, content/browser,
  model/tool/data, or identity/action boundary.
- **Lifecycle:** ordering, replay, timing, state transition, storage, delivery,
  export, cache, worker, and delayed consumer behavior.
- **Business model:** ownership, price, entitlement, approval, privacy,
  inventory, payment, moderation, collaboration, or other product invariant.

Preserve all plausible, evidence-grounded hypotheses; prioritize live actions by
information gain, impact fit, ownership/scope safety, freshness, and overlap.

## Contextual research router

Retrieval is not a fixed staircase. Choose the source that answers the current
question:

- **MapStore:** concrete target facts, tested state, dedupe, coverage, defenses,
  and target-specific gadget context. Query with an explicit intent after a
  surface/route/technology/role question is known.
- **Source or JS analysis:** exact implementation, library configuration, call
  sites, and source-to-consumer path.
- **ResearchMap:** portable cited mechanisms, code signals, and test directions
  matching observed technology or behavior.
- **Preview MCP / independent web research:** external write-ups, emerging
  technology knowledge, upstream documentation, advisories, and analogous
  mechanisms when local knowledge is thin or a current question remains open.
- **Specialist skill:** a confirmed or likely class/component boundary with a
  concrete target hypothesis.

External material is hypothesis input, never proof of target behavior. Convert it
into one explicit, scoped target hypothesis and use the smallest meaningful
safety-compliant discriminator.

Before declaring a structurally plausible goal-run line exhausted, ensure the
relevant input treatment and consumers are understood, representative distinct
discriminators were tried, no named wake condition remains, and appropriate
ResearchMap/Preview/web research occurred when there was no next grounded test.

## Run state and promotion

Maintain: current surface, selected lens, fresh observations, active/deferred
hypotheses, pressure (`cold`/`warm`/`hot`), current retrieval decision/reason, and
next discriminator.

- Write durable target facts, coverage, and useful negative results to MapStore.
- Keep hunt chronology, decisions, and handoffs in bounty notes/Hunter Memory.
- Keep portable cited mechanisms in ResearchMap.
- Keep exact attempts/evidence in the appropriate program artifact lane.

Do not create a competing permanent knowledge store from the goal state.

## Related skills

- If a hunt goal is about to be called done and another consumer, API, parameter,
  or JavaScript corpus might still serve it, load `surface-expansion`.
- If the runtime map is thin, load `live-map`.
- If an observed component could change the next decision, load `technology-research`.
- If a filter, parser, or access control stopped the path, load `bypass`; if the
  obstacle is a WAF or payload filter, load `waf`.
- If an auth or role state is untested, load `access-control`. If a client claim's
  server enforcement is unproven, load `assumption-testing`.
