---
name: rce-lifecycle
description: "Trace RCE candidates through later consumers safely."
version: 0.1.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, rce, lifecycle, async, consumers]
    related_skills: [rce, rce-exploration, rce-surface-mapping]
---

# RCE Lifecycle Expansion

Load when a controlled value is stored, converted, queued, previewed, imported,
or otherwise plausibly reaches a later consumer. This packet owns lineage and
consumer branching, not proof of execution.

## When to Use

- A controlled value is stored, transformed, queued, previewed, imported, or consumed later.
- A first consumer is inert but later processing remains plausible.

## Lineage Packet

```text
producer/write primitive and owned resource
marker/control identifier and observed representation
transforms and current consumer
possible later consumers and trigger timing
process/ownership/cleanup state
next safe observation per branch
```

## Expansion Loop

1. Identify relevant transitions: storage, metadata extraction, AV/OCR,
   preview/transcoding, archive expansion, export/email, queue/job, retry,
   webhook, deployment, or worker hand-off.
2. Observe only owned/approved consumers. A later consumer is a branch, not
   proof the producer is executable.
3. Preserve the original representation and each transform. Reclassify type,
   parser, and privilege context at every consumer.
4. Route a branch to `rce-surface-mapping` for renewed lead generation or
   `rce-validation` when the branch has a concrete execution question.

## Boundaries

Do not create public/staff-visible or difficult-to-clean artifacts. Do not infer
RCE from upload acceptance, persistence, parser errors, or a job trigger alone.

## Completion

Every discovered consumer is mapped, safely unavailable with reason, or has an
exact next observation and owner.
