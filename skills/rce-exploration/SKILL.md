---
name: rce-exploration
description: "Route authorized RCE investigation into focused packets."
version: 0.3.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, rce, injection, validation, evidence]
    related_skills: [rce, general-security-testing-policy, injection-testing-policy, attempt-recording-policy, rce-surface-mapping, rce-lifecycle, rce-validation, rce-technology-research]
---

# RCE Primitive Exploration

RCE investigation starts at `rce`. Load this packet for a named
source-to-executor hypothesis: classify the suspected execution path, dispatch
a focused next question, and synthesize the result. It is not a
payload catalog or an instruction to reproduce public exploit chains.

## When to Use

- A mapped input may reach an OS command, evaluated code, template engine,
  deserializer, parser/converter, lookup/config language, plugin, job runner,
  or deployment hook.
- A public advisory or source review identifies a plausible execution primitive.
- A chained finding may cross a server-side execution boundary.

Do not use for generic endpoint fuzzing without a plausible control/sink. Start
with `injection-testing-policy` or the class skill until a concrete RCE question
exists.

## Required Preflight

1. Load `general-security-testing-policy`, then `live-testing-policy` for any
   target interaction.
2. Load `injection-testing-policy` and `attempt-recording-policy` before a
   deliberate mutation sequence.
3. Use existing application mapping as input: `/appmap` for local source,
   `/live-map` for runtime routes/flows, and `/mental-map` for replayable
   workflow detail. Establish scope, owned resource, rate, baseline, and a named
   primitive question. A concrete sink need not already be evidenced: bounded
   precursor probes may create that evidence. Public reports provide research
   leads, never proof for a different target.
4. After a plausible RCE chain emerges, load `hypothesis-expansion-policy`; it
   owns candidate preservation, negative-result interpretation, pivots, and
   continuation records.

## Packet Routing

Load the packet that owns the **next** question; the parent retains
scope, synthesis, execution decisions, and closure.

| Signal | Load | Returns |
|---|---|---|
| Need routes, flows, state, source, or runtime technology facts | `/appmap`, `/live-map`, or `/mental-map` | Reusable application map and bounded handoff context |
| Application mapping or technology evidence is available and RCE coverage needs leads | `rce-surface-mapping` | Candidate RCE primitive packets across mapped consumers |
| Round-tripped state or a nested blob may be reconstructed as runtime objects | `rce-deserialization` | Accepted-control, integrity, object-loader, and trigger analysis |
| A marker or file is stored, queued, transformed, previewed, imported, or later-consumed | `rce-lifecycle` | RCE-specific producer/consumer lineage and branch packets |
| A plausible primitive needs a low-impact precursor, differential, or bounded proof | `rce-validation` | Probe ladder, baseline/control/result, confidence label, cleanup, closure |
| An observed stack, dependency, parser, runtime, configuration, or advisory changes feasibility | `rce-technology-research` | Source-backed mechanism and target precondition matrix |
| The control is specifically SSTI, XXE, SSRF, LFI, upload, or a defense boundary | Add the matching class skill/policy | Class-specific control evidence |

Packets are composable but not automatic. Return to this packet after each one;
branch only when the returned evidence creates a distinct source/consumer or
primitive question.

## Parent Working Loop

1. **Map:** identify attacker control, transformations, candidate executor,
   trigger, execution context, and prerequisites.
2. **Classify:** distinguish command/process use, code evaluation, template
   source, deserialization, parser/converter, lookup/config, and worker/build
   behavior. Do not collapse them into vague “RCE.” For the active primitive,
   retain a branch map of source/field, representation/transform, consumer/API,
   trigger/timing, execution context, and observation channel.
3. **Branch:** trace later consumers when the value persists or moves across
   services. Preserve representation and ownership; use
   `hypothesis-expansion-policy` for continuation and closure decisions.
4. **Explore then validate:** send a bounded precursor when it can distinguish
   a plausible RCE primitive without persistence, sensitive reads, or disruptive
   effect; follow signal with baseline/control validation and stop at the first
   sufficient evidence.
5. **Close:** report `cold`, `blocked`, `known exposure`, or `confirmed bounded
   impact`, with the exact remaining prerequisite or cleanup state.

## Shared Resources

Load a resource only when it answers the packet’s concrete question:

- `references/surface-map.md` — execution-capable sink families and transforms.
- `references/primitive-branch-map.md` — source-to-observation branches for a
  plausible RCE primitive.
- `references/validation-ladder.md` — confirmation hierarchy and safe stop boundary.
- `references/precursor-ladder.md` — how to create low-impact primitive signal before proof.
- `references/precondition-matrix.md` — runtime/deployment/privilege evidence.
- `references/evidence-and-closure.md` — false-positive and closure checklist.
- `references/research-map.md` — canonical technique references and research questions.
- `references/case-study-index.md` — source-verified public-chain lessons.

## Safety Boundaries

Do not create execution-environment persistence, access secrets, enumerate the
host/filesystem, open interactive shells, change privilege, move laterally,
trigger broad workers, or affect non-owned resources. Normal application-state
writes—such as an owned form submission or upload—remain eligible when they
are necessary to exercise the named primitive on a verified owned/disposable
fixture and remain within the live policy.

## Completion

An RCE investigation is complete only when its final state includes a scoped
control/sink hypothesis, baseline and negative control, context/preconditions,
a controlled signal or exact closure reason, cleanup status, and the
canonical attempt evidence.
