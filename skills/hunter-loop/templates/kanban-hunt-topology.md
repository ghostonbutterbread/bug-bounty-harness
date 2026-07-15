# Hunter Loop Kanban Hunt Topology

> Start with the minimum graph. Add a specialist only after the cold-surface map
> provides a concrete trigger.

## 0. Scope and account gate

- **Assignee:** coordinator
- **Dependencies:** none
- **Goal:** verify scope, rules, rate constraints, owned account/resource
  aliases, and approved auth-seed references.
- **Completion:** a sanitized scope/account summary is available; live cards can
  reference it. Otherwise all live cards remain blocked.

## 1. Cold-surface map

- **Assignee:** companion scout or coordinator
- **Depends on:** scope/account gate
- **Goal:** make 3–5 fresh observations in one selected flow before looking for
  historical leads.
- **Completion:** routes, parameters, roles/objects, consumers, and current
  behavior are recorded; MapStore is queried only for targeted dedupe/coverage.

## 2. Evidence-backed specialists (0–3 parallel)

- **Assignee:** appropriate specialist profiles
- **Depends on:** cold-surface map
- **Goal:** answer one narrow, observed security question each.
- **Constraints:** no duplicate surface lease; no generic class fan-out; each
  uses the Kanban Task Packet.
- **Completion:** structured result with pressure state and artifact pointer.

## 3. Independent verifier (only for candidates)

- **Assignee:** verifier
- **Depends on:** candidate specialist card
- **Goal:** independently reproduce the claimed behavior using the same scope,
  rate, and owned-resource constraints.
- **Completion:** confirmation, bounded rejection, or a documented blocker.

## 4. Synthesis and memory promotion

- **Assignee:** coordinator/synthesizer
- **Depends on:** completed specialist cards and verifier where applicable
- **Goal:** decide what is durable, what may chain, and what surface comes next.
- **Completion:** stable facts promoted to MapStore, narrative/handoffs to
  Bounty Notes, verbose evidence retained in artifacts, and next card(s) or a
  stop reason recorded.

## Suggested initial board

```text
[gate] scope-and-account context
  -> [map] cold map: <selected flow>
      -> [spec] <evidence-backed question A>
      -> [spec] <evidence-backed question B, only if independent>
          -> [verify] reproduce candidate(s), if any
              -> [synth] merge results / chain review / choose next surface
```

## Escalation rules

- A worker needing credentials, a CAPTCHA, a destructive action, a policy
  decision, or a different scope blocks the card and leaves a concise handoff.
- A `warm` or `hot` lane stays on its current bounded question until it reaches
  a discriminating probe, policy gate, or stop condition; do not let it branch
  into unrelated testing.
- A `cold` or `exhausted` lane returns to synthesis for a new selected surface.
- No finding is promoted from the specialist card alone; candidate findings get
  an independent verifier card.
