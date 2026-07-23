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
`~/projects/bug_bounty_harness/skills/bug-goals/`; do not place goal-routing,
research-escalation, or hunt orchestration in the AI Policies repository. AI
Policies may define safety boundaries and the meanings of knowledge sources, but
must not own bug-bounty goal workflow.

This skill is a goal router. It does not replace `general-security-testing-policy`,
`live-testing-policy`, `hunter-loop`, `map-store`, or specialist skills. Use the
BBH helper named `scripts/goal_router.py`, not `goal.py`, to avoid ambiguity with
Hermes, Codex, and Claude standing-goal commands.

Use the BBH helper to produce an auditable plan before the first target action:

```bash
cd ~/projects/bug_bounty_harness
python3 scripts/goal_router.py plan --program <program> --objective "<goal>" \
  [--url "<url>"] [--class <vulnerability-class>]
```

Use `init` only after choosing the approved run-artifact directory. It writes
routing state only; durable target truth belongs in MapStore.

## Goal modes

### Broad program

Trigger: generic objectives such as “find a vulnerability.”

Load Hunter Loop as the parent cadence. Begin with scope, cold recon/live map,
fresh observations, and a chosen surface plus lens. Do not start from broad
historical lead retrieval or assume a vulnerability class before current evidence
justifies one.

### Focused surface

Trigger: a named URL, feature, workflow, or vulnerability class.

Map the normal workflow and exact input → transformation → consumer path. Use
targeted MapStore facts and a relevant specialist skill. Do not launch broad recon
or a multi-surface campaign unless the evidence requires it.

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
