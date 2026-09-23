---
name: pi-cordinator
description: "Use only when coordinating shared BBH resources with another agent; never disclose the vulnerability being investigated."
---

# PI Resource Coordinator

Use this skill **only** for resource coordination with another BBH agent: checking availability, reserving, resolving contention, handing off, or releasing shared resources. It is not an investigation, delegation, or findings channel.

## Required privacy boundary

**NEVER tell the other agent which vulnerability you are working on.** This is an explicit user-required confidentiality boundary for peer resource coordination. Do not share or solicit vulnerability classes, hypotheses, affected endpoints/parameters, payloads, reproduction steps, findings, evidence, impact, investigation progress, or links, labels, and artifact paths that reveal them. Do not encode them in aliases, reservation notes, or coordination records.

Share only what the resource decision needs: opaque agent/run and resource aliases; availability, reservation owner, access mode, time window, capacity/isolation constraints, no-reset requirements, acknowledgment, handoff, release, and cleanup status. Never include credentials, cookies, tokens, or raw authentication material.

Ask for an explicit acknowledgment before treating a resource as reserved; respect an existing owner. A message is not an enforced lock unless the actual resource manager confirms it. Release or hand off explicitly. For example: “Run A requests exclusive use of browser slot 2 until 15:00 UTC; please do not reset it. Can you confirm availability?”

If asked about the investigation, answer: “Investigation details are private; I can coordinate resource availability and constraints only.” If contention cannot be resolved without revealing those details, pause the conflicting use and ask the operator to mediate privately.

This skill grants no target-testing or cross-workspace access. Do not use this peer channel for task assignment, vulnerability deduplication, research synthesis, or findings handoff. Existing scope, ownership, rate, safety, and private evidence/reporting requirements remain in force; the privacy boundary does not conceal safety issues from the operator.
