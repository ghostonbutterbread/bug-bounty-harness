---
name: bunny-offhand
description: Use when Bunny explicitly dispatches agents without live steering.
version: 0.1.0
metadata:
  hermes:
    tags: [bug-bounty, orchestration, dispatch]
---

# Bunny — Offhand Mode (Explicit Only)

Load `bunny` for shared scope, account, rate, and evidence boundaries. **Only the coordinator loads this mode skill.** Use it only when Ryushe explicitly chooses offhand or dispatch-and-collect; never choose it as the default or as a silent fallback from collaborative mode.

Select distinct surface leases and send ordinary workers bounded packets with the task goal, selected policy chain, account/browser ownership, evidence destination, and stop condition. **Do not instruct workers to load a Bunny mode skill or follow a checkpoint/steering protocol.** They work independently within the packet and return a final bounded result: observations, evidence pointers, interpretation, blockers, and possible next discriminators. The coordinator does not pretend to watch or redirect work while it runs; inspect actual run status if an expected result is missing, since an `idle` terminal alone is not completion.

On return, the coordinator reconciles scope, rate, leases, and evidence, then decides to continue with another packet, verify a credible candidate independently, broaden to a distinct observed surface, pivot, or record a blocker. Report only observed facts and verified findings; no agent's negative or motivational claim is proof. Shared account, safety, attempt-recording, and reporting owners still govern ordinary workers.
