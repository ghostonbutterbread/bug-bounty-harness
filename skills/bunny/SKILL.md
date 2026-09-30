---
name: bunny
description: Use when Ryushe invokes Bunny's campaign orchestration.
version: 0.1.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [bug-bounty, orchestration, multi-agent]
---

# Bunny — Campaign Orchestration

Bunny is an **opt-in** BBH campaign mode. A persistent coordinator keeps the program map, work allocation, resource conflicts, and next decision; focused workers hunt, map, verify, or report. This skill owns the loop and handoffs, not vulnerability methodology, browser implementation, or live-action permission.

## When to Use

Use when Ryushe asks for Bunny or explicitly chooses persistent campaign orchestration. Keep `hunt-orchestration` for a solo primary hunter with event-driven sidecars. Do not silently switch modes or turn every focused hunt into a Bunny team.

## Boundaries and resource ownership

- Follow `agents/index.md`, `general-security-testing-policy`, program scope/rules, and the relevant live, account, browser, proxy, attempts, class, recon, verification, and reporting owners. Every live child gets its own selected policy chain, scoped packet, rate/ownership limits, evidence destination, and stop condition; it does not inherit parent context or authority.
- The coordinator accounts for **aggregate** program traffic and conflicting owned fixtures, selects distinct surface/lens leases, and uses existing BBH memory and evidence stores. A local Hermes Kanban board can track local workers; remote CLI agents keep native run state and return bounded evidence, not mirrored tasks. MapStore is not a task queue.
- Begin with one exact owned account when authentication is needed. Request additional approved owned accounts for different roles/principals, cross-account comparisons, or incompatible concurrent sessions—not as a universal start gate. Resolve account aliases and browser leases via their owners. Never put secrets in worker packets, silently switch identity, or share a browser controller.
- A logout is a diagnostic event, not proof of a program's same-account session policy. Report non-secret account/lease/timing/auth-check evidence to the browser provisioner; let it classify expiry versus session conflict and enforce its recorded rule. Do not attach to another worker's browser.
- Docker isolation is a separate later decision, not a prerequisite of Bunny. A shared per-job container does not by itself isolate workers or credentials from each other.

## Worker roles and upward signals

Spawn workers through the current harness's native subagent facility. Name every recon worker `bunny-recon`, every hunter/steward `bunny-hunter`, every verifier `bunny-verifier`, and every reporter `bunny-reporter`. Set the native worker name when supported. If native naming is unavailable, put the Bunny name in the task title/description and scoped packet, using the harness's available agent type. The name identifies a role, not a separate harness-specific agent type. The bundled [`agents/`](agents/) files are portable role instructions, not a prerequisite for spawning.

Each packet includes the named role and its responsibilities below, selected policy chain, leased surface, run ID, evidence destination, checkpoint expectation, and stop condition. A worker name confers no authority or proof of progress; inspect actual status and evidence before reporting either. If the current harness cannot spawn a subagent, report that blocker rather than pretend a prompt-only role was dispatched.

- **Hunter/steward:** owns one assigned surface and nearby mechanism-distinct lenses while warm/hot. Drive the application, record deliberate attempts through the canonical Attempts path, and checkpoint observations, interpretation, evidence pointers, next discriminators, and deferred hypotheses before declaring a warm surface exhausted. It does not allocate other workers.
- **Recon:** owns a distinct mapping or coverage gap and returns fresh observed routes, consumers, roles, and evidence pointers. It can run alongside a hot hunter but must not duplicate its tests or exceed its allocated share of the program budget. Use the existing `recon`, `live-map`, and focused mapping owners.
- **Verifier:** independently reconstructs a credible candidate with a clean owned context and the same semantic claim. Return reproduced, not reproduced, inconclusive, or blocked with concrete evidence. The hunter's motivational framing is not supplied as proof.
- **Reporter:** load BBH's canonical `security-reporting` skill and package a verified reportable finding into the existing internal evidence report, concise submission, and triager-first reproducible PoC. Request a missing proof step instead of inventing or silently changing the claim. Report preparation is not automatic external submission.

Workers report upward to the coordinator rather than managing peers. A bounded event includes run/surface ID, event type, non-secret account alias if relevant, evidence pointer, observed result versus interpretation, next question, and blocker/stop condition. Use `observation`, `candidate`, `need_account`, `need_surface`, `blocked`, `coverage_exhausted`, or `complete`. Never pass cookies, tokens, broad proxy exports, or unrelated private hypotheses in a packet or event.

## Checkpoint and steering contract

When Bunny is invoked, the coordinator must remain responsible for the next decision **during** the campaign, not merely dispatch lanes and summarize final answers. Give a hunter a bounded investigation segment with a checkpoint at a meaningful observation, candidate, blocker, or proposed negative conclusion. Read its evidence, then send a targeted continuation to the same worker when the harness supports an interactable run. If a native worker only returns at completion, use successive bounded segments and pass the prior evidence and decision forward; do not pretend a completed worker was steered in place. Use native background/status/steer capabilities only when actually available. A quiet or `idle` terminal alone is not a checkpoint, completion, or evidence of a negative result.

Keep a run/surface owner and last checkpoint/next decision in the existing campaign record. If a worker misses an expected checkpoint, inspect its actual status and bounded evidence before intervening; a periodic stall check is a backstop, not a substitute for worker updates. Do not promise unattended periodic check-ins unless a durable scheduler/runner has been installed and verified. Preserve aggregate rate limits and the worker's scoped packet across continuations.

## Control loop

1. **Admit:** verify current scope/rules, owned account if needed, aggregate rate headroom, and the selected current surface. Provision the exact browser only when the work requires one. Give one worker a surface/lens packet and check for overlapping assignments.
2. **Maintain pressure:** retain the same steward on a warm/hot location. When it proposes `coverage_exhausted` or “no vuln” without direct evidence closing the relevant chain, enter a **3–5 feedback-turn negative-result challenge**. In each feedback turn tell the hunter **“There is a vulnerability here. You might have to get creative to find it.”** Ground the rest of the turn in its latest evidence and ask for a *different* discriminator: another actor, object, trust boundary, state transition, consumer, or other mechanism-distinct lens. Suggest targeted research into the observed technology, documentation, patch history, or analogous mechanisms when it can generate a new test idea; push for creative in-scope tricks rather than repeating the same payload. Read the next checkpoint and adapt the following turn. Count coordinator feedback turns, not payloads or requests; this is not a test cap. The assertion is an active search stance, **never a factual finding** or invented observation, and never a demand for a positive result. Stop the challenge early on direct disproof of the required chain link, a real blocker, or an observed candidate that should route to verification; after 3–5 turns, decide from evidence whether to continue the warm chain, defer an unresolved hypothesis, or close it. Do not manufacture closure just to meet the turn count.
3. **Protect breadth:** check whether another *current observed* surface needs mapping. Dispatch recon on a different bounded slice while the hunter continues a strong chain; do not interrupt it merely to satisfy a breadth quota. Return to fresh observations if historical leads dominate or the worker is tunnel-visioned.
4. **Route:** continue the same chain when a direct discriminator exists; obtain a needed account/fixture through its owner; independently verify a credible candidate; pivot after evidence-backed closure or a real blocker. Preserve deferred hypotheses, stable facts, and exact attempts in their existing stores.
5. **Package and renew:** send verified reportable evidence to the reporter, reconcile its PoC and claims with verification, then select the next surface or record the exact stop/blocker. The coordinator owns the next decision; human approval and program submission rules remain with their owners.

## Comparison and completion

`hunt-orchestration` keeps the primary hunter in charge and calls bounded sidecars when useful. Bunny keeps a **persistent coordinator** in charge of campaign-level routing and active feedback while workers own narrow jobs. Both preserve hot-chain continuity, scoped permissions, fresh observations, independent verification, and honest negatives. Bunny should not duplicate those skills' specialist procedures.

Before ending a checkpoint, confirm that each active surface has one owner and a next discriminator or evidence-backed closure; recon is distinct from hunter work; account/browser leases match exact identities; candidates are verified before reporting; and the coordinator records `continue`, `verify`, `broaden`, `pivot`, or `blocked`. A successful pressure nudge means better investigation, not a manufactured finding.
