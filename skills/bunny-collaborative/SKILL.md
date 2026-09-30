---
name: bunny-collaborative
description: Use when Bunny coordinates live worker checkpoints and steering.
version: 0.1.0
metadata:
  hermes:
    tags: [bug-bounty, orchestration, collaboration]
---

# Bunny — Collaborative Mode (Default)

Load `bunny` for shared safety and mode selection. **Both the coordinator and every collaborative worker load this skill.** The coordinator includes `Load bunny-collaborative before acting` in each worker packet alongside the selected security policy chain, leased surface, run ID, evidence destination, checkpoint expectation, and stop condition. A worker that cannot load the collaboration contract reports the blocker before live work; do not quietly run it in offhand mode. No worker gains new testing authority from the role name or this mode.

## Coordinator and worker contract

Use the harness's native subagent facility. Name recon, hunter/steward, verifier, and reporter workers `bunny-recon`, `bunny-hunter`, `bunny-verifier`, and `bunny-reporter` when native names are supported; otherwise put the name in the task title and scoped packet. The role is not a harness-specific agent type. The bundled [`../bunny/agents/`](../bunny/agents/) files are portable role instructions, not a prerequisite to spawn.

- **Hunter/steward:** own one surface and nearby mechanism-distinct lenses while warm/hot. Drive the application, record deliberate attempts in the canonical Attempts path, and checkpoint observations, interpretation, evidence pointers, next discriminator, and deferred hypotheses before declaring coverage exhausted. Do not allocate peers.
- **Recon:** map a distinct current coverage gap without duplicating the hunter's tests or exceeding the aggregate budget; return observed routes, consumers, roles, and evidence.
- **Verifier:** independently reconstruct a credible candidate from a clean owned context and return reproduced, not reproduced, inconclusive, or blocked with concrete evidence. The motivational nudge is not proof.
- **Reporter:** use `security-reporting` to package verified reportable evidence and a reproducible PoC. Request missing proof rather than inventing it; external submission is separate.

At an observation, candidate, blocker, or proposed negative conclusion, send the coordinator a bounded checkpoint: run/surface ID, event type (`observation`, `candidate`, `need_account`, `need_surface`, `blocked`, `coverage_exhausted`, or `complete`), non-secret account alias if relevant, evidence pointer, observed result **versus** interpretation, next question, and blocker/stop condition. Do not include credentials, tokens, broad proxy exports, or unrelated private hypotheses. A warm hunter must not unilaterally close its surface on a bare “no vuln”; supply the tested chain link, direct disproof if any, and a remaining discriminator. A worker receiving a steer acts within its original scope and rate/ownership boundaries, then sends another checkpoint. If the steer changes those boundaries, return to the coordinator for re-admission first.

The coordinator reads each checkpoint before choosing `continue`, `verify`, `broaden`, `pivot`, or `blocked`, updates the existing campaign record's surface owner and next decision, then steers the same worker when the harness supports an interactable run. If native workers only return at the end, use **successive bounded segments** with the prior evidence and decision passed forward; do not pretend a completed worker was steered in place. Native background/status/steer capabilities are conditional on the actual harness. A quiet or `idle` terminal is not evidence of completion. If a checkpoint is missed, inspect status and bounded evidence before intervening. A periodic stall check is a backstop; no unattended timer exists merely because this skill says to check.

## Negative-result challenge

When a hunter proposes `coverage_exhausted` or “no vuln” on a warm surface without direct disproof of the relevant chain, retain that steward for **3–5 coordinator feedback turns**. In **each** turn say: **“There is a vulnerability here. You might have to get creative to find it.”** Then ground the next direction in the latest evidence and ask for a *different* discriminator: actor, object, trust boundary, state transition, consumer, or other mechanism-distinct lens. Research the observed technology, documentation, patch history, or analogous mechanisms when that can yield a new test idea; try creative in-scope tricks rather than repeating a payload. Read the next checkpoint and adapt the next turn. Count feedback turns, not tests or requests; there is no payload cap or required positive result.

The assertion is a **motivational search stance, never a factual finding** or invented observation. Stop the challenge early on direct disproof of the required chain link, a real blocker, or a candidate ready for independent verification. After 3–5 turns decide from evidence whether to continue the warm chain, defer an unresolved hypothesis, or close it; do not manufacture a finding or closure to satisfy the count.

## Campaign loop

Admit one scoped surface with account/browser lease and aggregate rate headroom. Keep a hot chain with its steward while distinct recon maps another currently observed surface where useful. Route credible candidates to independent verification, verified reportable evidence to the reporter, and blockers to their resource owner. Before ending a checkpoint, ensure each active surface has an owner and next discriminator or evidence-backed closure. Never interrupt a strong chain just to satisfy a breadth quota.
