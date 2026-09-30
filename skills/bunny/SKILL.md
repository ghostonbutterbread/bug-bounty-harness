---
name: bunny
description: Use when Ryushe invokes Bunny's campaign orchestration.
version: 0.2.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [bug-bounty, orchestration, multi-agent]
---

# Bunny — Mode Router

Bunny is an **opt-in** BBH campaign mode. A coordinator owns the program map, work allocation, resource conflicts, and next decision. Use it when Ryushe asks for Bunny or explicitly chooses campaign orchestration; do not silently switch an ordinary hunt into Bunny. Keep `hunt-orchestration` for a solo primary hunter with event-driven sidecars.

## Select one mode

- **Default: collaborative.** When Bunny is invoked without a mode, load `bunny-collaborative` before dispatch. The coordinator and each collaborative worker must load that skill: it defines checkpoints, upward evidence, steering, and the negative-result challenge. Name the mode and its worker load requirement in each packet.
- **Explicit: offhand.** Only when Ryushe selects offhand/dispatch-and-collect, load `bunny-offhand` in the coordinator. Its ordinary workers receive scoped tasks and applicable security policies, **not** a Bunny mode skill or collaboration contract.
- A mode change occurs at an evidence checkpoint, after reconciling the current worker and surface lease. Do not silently fall back from collaborative to offhand when a transport or worker skill is unavailable; report the limitation and seek a workable collaborative channel or an explicit mode change.

## Shared boundaries

Follow `agents/index.md`, `general-security-testing-policy`, published program scope/rules, and the relevant live, account, browser, proxy, attempts, class, recon, verification, and reporting owners. Every live worker gets its own selected policy chain, scoped packet, rate/ownership limits, evidence destination, and stop condition; it does not inherit the coordinator's context or authority. The coordinator accounts for **aggregate** program traffic, conflicting owned fixtures, and distinct surface leases. Use existing BBH memory and evidence stores; MapStore is not a task queue.

Begin with one exact owned account when authentication is needed. Request another approved owned account for distinct roles/principals, cross-account comparisons, or incompatible sessions—not as a universal start gate. Never put secrets in packets, silently switch identity, or share a browser controller. A logout is a diagnostic event for the browser provisioner, not proof of a same-account session rule. Docker isolation is a separate decision, not a prerequisite of Bunny.

Workers' observations and evidence are not findings by themselves. Independently verify credible candidates before report preparation; follow canonical `security-reporting`, and do not automatically submit externally. The coordinator records the next decision and preserves exact attempts, stable facts, and deferred hypotheses through their existing owners.
