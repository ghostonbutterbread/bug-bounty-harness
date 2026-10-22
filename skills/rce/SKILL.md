---
name: rce
description: "Route server-side code execution research and validation."
version: 0.1.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, rce, command-execution, code-execution]
    related_skills: [rce-exploration, rce-surface-mapping, rce-deserialization, rce-lifecycle, rce-validation, rce-technology-research]
---

# Remote Code Execution

Use when the question is whether attacker-controlled input can become instructions
in a server-side process or later worker. RCE is a trust-boundary failure: data
crosses into a command, code evaluator, template source, deserializer, converter,
plugin, or job runner under an execution identity the attacker should not control.
The question is not merely whether a payload was accepted, but **which controlled
value reaches which executor, by which transform and trigger, with what observable
effect and authority**. A client-side script effect is XSS, not server-side RCE.

## Where to Look

Process helpers and diagnostics; document/media conversion and archive extraction;
template/report generation; typed imports and deserialization; upload previews;
webhooks, automation, plugin/config loaders, queues and deployment/build workers.
These are recognition cues, not a claim that every such feature executes code.
`rce-surface-mapping` owns the fuller consumer inventory.

## Route by the Next Question

- Need app routes, controlled fields, or consumers? Map with `live-map` or `appmap`,
  then load `rce-surface-mapping` to derive candidate execution paths.
- Have a particular source-to-executor hypothesis? Load `rce-exploration` for
  primitive classification, branch selection, and an investigation packet.
- State may be reconstructed as runtime objects, including inside cookies or
  headers? Load `rce-deserialization` for representation, accepted control,
  integrity boundaries, and the actual object-loading trigger.
- Value is stored, transformed, queued, previewed, or consumed later? Load
  `rce-lifecycle` for producer-to-consumer lineage.
- Observed stack or advisory changes feasibility? Load `rce-technology-research`
  for source-backed preconditions; version or public PoC alone is not target proof.
- Need a precursor, differential, or bounded confirmation? With a named,
  plausible source-to-executor question from this class entry, mapping, or
  `rce-exploration`, load `rce-validation`. If the candidate lacks that chain,
  clarify the primitive with `rce-exploration` first. Preserve a normal baseline,
  inert control, observation channel, and exact stop.
- For a specific input boundary such as SSTI, upload, LFI, SSRF, or XML parsing,
  also load its class skill and applicable AI Policies. Those skills own the
  mechanism; this entry owns the execution-chain question.

Do not infer execution from upload acceptance, parser errors, template-looking
output, a scheduled job, or a blind response alone. A failed first consumer does
not close a later consumer. Preserve unknown preconditions and alternative
explanations rather than converting a search miss into target evidence.

## Authority and Closure

Before any live target action, load `general-security-testing-policy` and
`live-testing-policy`; apply `injection-testing-policy`, account/resource, rate,
and attempt-recording rules to deliberate probes. Map owned fixtures and avoid
host enumeration, secrets, execution persistence, shells, privilege changes,
lateral movement, broad worker triggers, or non-owned effects. Prefer bounded,
non-disruptive discriminators and stop at sufficient evidence. A potentially
destructive proof belongs in an authorized disposable local instance or stops
with its exact blocker; a local result is not production proof.

Return the controlled source, transform, executor/trigger, execution context,
baseline and negative control, observation or precise gap, confidence/closure,
cleanup status, and evidence pointers. Keep source-backed mechanisms in focused
references rather than growing a payload/tricks catalog in this entry.
