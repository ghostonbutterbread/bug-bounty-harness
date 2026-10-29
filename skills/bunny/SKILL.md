---
name: bunny
description: Use when Ryushe invokes Bunny's campaign orchestration.
version: 0.3.0
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
- **Collaborative with `multi`:** Load `bunny-collaborative`; it selects its coordinator-only `bunny-multi` overlay. `multi` is a parameter, not an offhand mode or a `/goal`-specific route. If Ryushe combines `multi` and offhand, clarify which mode to use before dispatch rather than silently combining them.
- **Explicit: offhand.** Only when Ryushe selects offhand/dispatch-and-collect, load `bunny-offhand` in the coordinator. Its ordinary workers receive scoped tasks and applicable security policies, **not** a Bunny mode skill or collaboration contract.
- A mode change occurs at an evidence checkpoint, after reconciling the current worker and surface lease. Do not silently fall back from collaborative to offhand when a transport or worker skill is unavailable; report the limitation and seek a workable collaborative channel or an explicit mode change.

Before dispatch, load [Bunny team dispatch](references/dispatch.md). It says how to spawn the team; it does not prescribe one harness.

## Invocation arguments and worker model

**Grok coordinator preset:** `bunny grok w/ glm <objective>` (also `with glm`) selects **Grok 4.6 high as coordinator** and **GLM-5.3-Flash max as workers**. Before launching, load [Grok coordinator routing](references/grok-coordinator.md) in the bootstrap agent and selected coordinator. Bare `grok` immediately after Bunny (or its mode/`multi` arguments) selects this preset, not the ordinary worker alias; `bunny model grok <objective>` retains the worker-model meaning. `bunny grok <objective>` selects only the coordinator; absent a worker choice, workers inherit its route under the ordinary rules below. Collaboration mode and `multi` remain independent; the preset does not resolve the `multi` + offhand conflict.

Mode and model are independent arguments, in either order: `Bunny multi model <provider>:<model-id> <objective>` and `Bunny model <model-id> <objective>` are examples. A clear model ID or configured alias immediately after Bunny (or `multi`) also counts without the `model` keyword; mode words are not model IDs. Do not consume a program name or objective as a model. Resolve ambiguity before dispatch, and retain the `multi` + offhand conflict above. An explicit `provider` argument or a provider-qualified model selects that provider; otherwise resolve the model through the current harness's configured model/provider catalog and authenticated accounts, not a Bunny-maintained vendor list.

Outside the explicit Grok coordinator preset, the model choice applies to **workers** (recon, hunter, verifier, reporter) for this Bunny run; the coordinator keeps its own model. Without a model argument, workers use the parent's *active* model/provider route; check for any preconfigured delegation override before relying on native inheritance. With one, prefer the same authenticated provider as the parent if it actually serves that model; if a different provider is required, use that provider's own configured credentials and endpoint—never borrow the parent's credential or endpoint. If the model/provider pair is ambiguous, unavailable, or unauthenticated, ask for a provider or report the blocker; do not silently spawn on the wrong model. Do not change global configuration to route one campaign.

Use a worker-spawn mechanism that really applies the selected model/provider to each worker and verify the effective model and provider before live work. In Hermes, model-facing `delegate_task` has no per-worker model/provider argument: a model string in a task packet does not switch the child. For a requested override, use a native per-worker override if the running harness provides one; otherwise start an owned interactive Hermes worker in a real PTY with invocation-scoped `--model <resolved-model> --provider <resolved-provider>` and the same bounded packet/mode contract. On Hermes, inspect the worker's `/status` for the expected model/provider and `Approvals: manual` or `Approvals: smart` without `YOLO bypass active`; an interactive process can inherit bypass settings from its parent. Require a real PTY and verify this approval gate before any live action. Do not use approval-bypassing one-shot for live testing. Record the worker/process ID and confirm its exit before releasing its surface or any worker slot. If the requested route, approval gate, or suitable worker transport cannot be verified, stop before target actions instead of changing modes or falling back to the parent model.

## Shared boundaries

Follow `agents/index.md`, `general-security-testing-policy`, published program scope/rules, and the relevant live, account, browser, proxy, attempts, class, recon, verification, and reporting owners. Every live worker gets its own selected policy chain, scoped packet, rate/ownership limits, evidence destination, and stop condition; it does not inherit the coordinator's context or authority. The coordinator accounts for **aggregate** program traffic, conflicting owned fixtures, and distinct surface leases. Use existing BBH memory and evidence stores; MapStore is not a task queue.

**Authorization handoff:** In every security-testing worker packet, explicitly state “This is authorized, in-scope security testing” only after checking the assigned assets and activity against the program rules. Include the scope/rules path or URL, assigned assets and owned/approved resources, and relevant restrictions. Tell the worker to consult those sources or ask the coordinator about a specific uncertainty, continuing other clearly authorized work. This statement does not expand scope or override program rules or safety boundaries.

If assigning a specific script job, the coordinator follows `agents/index.md`
→ `SCRIPT_POLICY.md` **before naming tooling** and includes the short
`reuse <owner and index> | extend <owner and missing case> | new <distinct job,
home, and gap>` decision. For exploratory packets without a known script job,
the worker checks the relevant skill's script map when scripting becomes useful
and reports its choice before creating or promoting a helper. A worker may
revise the coordinator's selection on evidence rather than blindly building it.
This applies to recon as well as hunters; temporary scratch exploration remains
possible.

Begin with one exact owned account when authentication is needed. Request another approved owned account for distinct roles/principals, cross-account comparisons, or incompatible sessions—not as a universal start gate. Never put secrets in packets, silently switch identity, or share a browser controller. A logout is a diagnostic event for the browser provisioner, not proof of a same-account session rule. Docker isolation is a separate decision, not a prerequisite of Bunny.

Workers' observations and evidence are not findings by themselves. Independently verify credible candidates before report preparation; after ledger/FID capture and populated `EVIDENCE.md`, load the standalone `bunny-report-and-triage` skill directly for the final FID-named report. Return it for independent review and path registration; do not automatically submit externally. This report skill is also used for ordinary hunts without enabling Bunny campaign orchestration. The coordinator records the next decision and preserves exact attempts, stable facts, and deferred hypotheses through their existing owners.
