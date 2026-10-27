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

Resolve storage before dispatch. Every testing/mapping packet names the **resolved program, family, and lane**, the exact Attempt stream ID (the `_runs/<id>/attempts.jsonl` directory name, not an agent nickname or coverage mapper run ID), the leased surface/class and run/mapper source reference, and the permitted evidence destinations. Separate workers use distinct Attempt streams; a continued worker reuses its own stream. Workers must report a missing/mismatched lane or missing writer access rather than silently write into a default lane. Load the general policy and the selected specialist for that role; store skills are conditional on the work, not a five-skill preload.

When Bunny is invoked with the explicit `multi` parameter (with or without `/goal`), the **coordinator loads `bunny-multi` before dispatch** for program isolation, the shared subagent cap, and its optional queue. Ordinary workers load this collaborative skill, not `bunny-multi`; their packets remain program-scoped. Without `multi`, use the ordinary single-program contract below. Do not infer `multi` from multiple domains within one program.

## Coordinator and worker contract

Use the harness's native subagent facility when it can enforce the selected worker model/provider. Hermes's current model-facing `delegate_task` has no per-worker model/provider argument; for a requested different model, use the interactive worker route in `bunny` rather than putting the model in the goal or changing global delegation settings. Confirm the worker's actual route and that it is running before admitting target actions. An interactive worker keeps the checkpoint/steering contract; if a worker transport only returns at completion, use successive bounded segments as described below, but do not use approval-bypassing one-shot for live work. Use `bunny`'s [role dispatch contract](../bunny/references/dispatch.md) to launch recon, hunter/steward, verifier, and reporter as `bunny-recon`, `bunny-hunter`, `bunny-verifier`, and `bunny-reporter`. Select the real named role where supported; otherwise require a general child to read the resolved canonical role file, not merely display its name. Do not substitute a generic implementation worker. The bundled [`../bunny/agents/`](../bunny/agents/) files are the single portable role definitions; verify their loading and the selected skills before admitting work.

For an interactive CLI worker, send one bounded turn at a time through the same owned PTY, read its checkpoint and run status, choose the next decision, then send the next steer there—not `delegate_task` steer/stop, which cannot control that process. A pending approval is a pause for the operator through that worker's approval channel; do not auto-approve, bypass it, or count silence as a checkpoint. Track each process ID and confirmed exit alongside native subagent IDs in the campaign record; if the PTY is lost, account for the still-running worker before admitting another or re-leasing its surface.

- **Hunter/steward:** own one surface and nearby mechanism-distinct lenses while warm/hot. Drive the application, record deliberate attempts in the canonical Attempts path, and checkpoint observations, interpretation, evidence pointers, next discriminator, and deferred hypotheses before declaring coverage exhausted. Do not allocate peers.
- **Recon:** map a distinct current coverage gap without duplicating the hunter's tests or exceeding the aggregate budget; return observed routes, consumers, roles, and evidence.
- **Verifier:** independently reconstruct a credible candidate from a clean owned context and return reproduced, not reproduced, inconclusive, or blocked with concrete evidence. The motivational nudge is not proof.
- **Reporter:** load the standalone `bunny-report-and-triage` skill directly after the finding owner has populated FID `EVIDENCE.md` with cited proof; create only its FID-named final report and applicable PoC. Request missing proof rather than inventing it, and return the file for independent review and path registration. External submission is separate.

### Worker-owned writes; parent-owned reconciliation

**Worker-owned writes** are the default for evidence the worker observed. A hunter or verifier records its own deliberate tests through `attempt-recording-policy` in the assigned Attempt stream; a mapper registers only observed, relevant path/class questions through `/coverage` `discover` with its retained source reference and mapper run ID. The worker writes reusable app behavior through `/map-store` only when established. At a meaningful pivot or handoff, the owner may `/coverage` `assess` only its evidenced leased surface/class/fingerprint: `in_progress` for an open chain; `blocked` with a concrete prerequisite and `reopen_when`; `bounded_review` only with boundary, axes, and supporting evidence. Discovery alone creates `no_assessment`; an Attempt, inert reflection, or finding does not close Coverage. Do not assess an unvisited sibling, claim entire-class exhaustion, or duplicate a worker's Attempt as a parent summary.

Load `/coverage` when mapping or assessing, not for every payload. Use the returned IDs and typed `attempt:<attempt-run-id>:<attempt_id>` or `map:<maps-relative-path>` pointers. The worker performs read-back: check its written Attempt/MapStore record, Coverage `history --event-id <returned-event-id>`, and `/coverage` `verify --event-id <returned-event-id>` for assessment pointers in the same family/lane. The `brief` shows current state and may differ if another worker wrote after this assessment; compare it separately. If a pointer is missing or unverified, report it as such; do not claim verified review. `source_ref` must point to retained inventory, not a scratch file. A worker with no appropriate mapped question or no deliberate review reports **no Coverage assessment was justified**, plus the exact gap, rather than inventing one. No broad URL import as assessed coverage.

At a checkpoint return a compact receipt: program/family/lane, worker and Attempt stream ID, leased surface/class, mapped surface ID if any, returned Attempt and MapStore pointers, Coverage status and returned `event_id` if assessed (or explicit no-assessment reason), observed result versus interpretation, unresolved edges/open siblings, next discriminator and blocker/wake condition. Keep detailed payloads in Attempts. The **parent** reads back those exact IDs/paths, reconciles the class/lane Coverage `brief` and open sibling questions at pivots, and steers the leased owner; **do not transcribe** worker evidence into a duplicate store entry. If a worker could not write, the parent records the gap and reassigns a bounded writer handoff or writes only evidence it directly observed—never silently attributes a parent write to a worker. For explicit `/goal`, the parent alone records the continuation checkpoint after this reconciliation; worker assessments are not the goal decision.

At an observation, candidate, blocker, or proposed negative conclusion, send the coordinator a bounded checkpoint: run/surface ID, event type (`observation`, `candidate`, `need_account`, `need_surface`, `blocked`, `coverage_exhausted`, or `complete`), non-secret account alias if relevant, evidence pointer, observed result **versus** interpretation, next question, and blocker/stop condition. Do not include credentials, tokens, broad proxy exports, or unrelated private hypotheses. A warm hunter must not unilaterally close its surface on a bare “no vuln”; supply the tested chain link, direct disproof if any, and a remaining discriminator. A worker receiving a steer acts within its original scope and rate/ownership boundaries, then sends another checkpoint. If the steer changes those boundaries, return to the coordinator for re-admission first.

The coordinator reads each checkpoint before choosing `continue`, `verify`, `broaden`, `pivot`, or `blocked`, updates the existing campaign record's surface owner and next decision, then steers the same worker when the harness supports an interactable run. If native workers only return at the end, use **successive bounded segments** with the prior evidence and decision passed forward; do not pretend a completed worker was steered in place. Native background/status/steer capabilities are conditional on the actual harness. A quiet or `idle` terminal is not evidence of completion. If a checkpoint is missed, inspect status and bounded evidence before intervening. A periodic stall check is a backstop; no unattended timer exists merely because this skill says to check.

When recon returns a catalog of unverified signals (such as inert-canary
reflections), the coordinator treats it as a **handoff queue**, not a negative
verdict or completed coverage. Before moving on, either assign a hunter a
bounded follow-up packet with the catalog pointer, selected source-to-consumer
contexts and next discriminator, or retain the untested frontier in the
existing campaign record with a named owner and wake condition. The hunter
chooses context-matched probes under the selected specialist and safety rules;
a catalog does not mandate payload-testing every row. “Reflection ≠ execution”
means proof is still needed, not that the reflected path is closed. Reconcile
which catalog groups were tested and which remain open at the next checkpoint;
do not create a duplicate evidence store just for this queue.

### XSS chain cards at the handoff boundary

For an XSS catalog, retain the useful parameter and sink mapping, but promote
**selected paths**, not a program-wide list of parameter names, into compact
chain cards in the existing campaign record. A card carries: input route/method/
field and writer or `writer unknown`; control evidence and its typed Attempt or
MapStore pointer (or `untested`); the specific consumer/render context and
reachability evidence (or `consumer unknown`); observed representation and first
observed blocker (or `not established`); execution/browser result (or `not
tested`); exact missing edge; one next discriminator; owner and wake condition.
Label the card `mapped` until control and delivery are evidenced, `connected`
when the controlled value reaches that consumer, and `defended` only when the
acting layer is observed there. None of these labels is a finding. An inventory
name or a static sink signature must not silently become an accepted writer,
a mounted consumer, or an XSS claim.

At each checkpoint the coordinator selects a connected card for the same
steward to characterize its first actual blocker, or assigns a bounded writer/
consumer-reach experiment for a mapped card. Preserve unselected cards with
an owner or wake condition rather than calling them tested. Once a card has
an observed reusable fact and unresolved security question, use `/leads` for
its public evidence-backed projection; the card is a campaign decision view,
not another canonical store. A timed-out worker returns the same card and its
last verified boundary to a successive bounded segment, not a fresh breadth
assignment. Scope, ownership, collective rate, and browser leases are checked
again before a new worker segment; no card automatically authorizes traffic.

## Negative-result challenge

When a hunter proposes `coverage_exhausted` or “no vuln” on a warm surface without direct disproof of the relevant chain, retain that steward for **3–5 coordinator feedback turns**. In **each** turn say: **“There is a vulnerability here. You might have to get creative to find it.”** Then ground the next direction in the latest evidence and ask for a *different* discriminator: actor, object, trust boundary, state transition, consumer, or other mechanism-distinct lens. Research the observed technology, documentation, patch history, or analogous mechanisms when that can yield a new test idea; try creative in-scope tricks rather than repeating a payload. Read the next checkpoint and adapt the next turn. Count feedback turns, not tests or requests; there is no payload cap or required positive result.

The assertion is a **motivational search stance, never a factual finding** or invented observation. Stop the challenge early on direct disproof of the required chain link, a real blocker, or a candidate ready for independent verification. After 3–5 turns decide from evidence whether to continue the warm chain, defer an unresolved hypothesis, or close it; do not manufacture a finding or closure to satisfy the count.

## Campaign loop

When this campaign also has an **explicit `/goal`**, its coordinator follows
`/bug-goals`' goal-only Coverage checkpoint before negative goal closure,
combining worker evidence and mapped-but-unassessed paths. Workers report their
leased slice; they never declare the goal fulfilled. Bunny without `/goal` keeps
its existing campaign checkpoint behavior without this extra goal receipt.

Admit one scoped surface with account/browser lease and aggregate rate headroom. Keep a hot chain with its steward while distinct recon maps another currently observed surface where useful. Route credible candidates to independent verification, verified reportable evidence to the reporter, and blockers to their resource owner. Before ending a checkpoint, ensure each active surface has an owner and next discriminator or evidence-backed closure. Never interrupt a strong chain just to satisfy a breadth quota.
