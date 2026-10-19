---
name: rce-surface-mapping
description: "Find RCE primitive leads across mapped app surfaces."
version: 0.2.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, rce, mapping, primitives, consumers]
    related_skills: [rce, rce-exploration, appmap, live-map, mental-map, class-derivation-policy]
---

# RCE Surface Mapping

Load from `rce` for broad mapped-surface coverage, or from `rce-exploration`
for a selected primitive branch, after `/appmap`, `/live-map`, `/mental-map`, source
review, runtime observations, or technology research. Its purpose is broad RCE
lead generation: examine the mapped application for every component that could
consume attacker-controlled data as instructions. It does not replace the
underlying application map or claim a lead is exploitable.

## When to Use

- An application map, flow map, source tree, proxy slice, or technology profile
  is available and RCE coverage needs ideas.
- A new feature, worker, parser, integration, framework, or material technology
  change expands the possible RCE surface.

## RCE Lead Inventory

Review mapped surfaces for these consumer families:

- process/command helpers, diagnostics, network tools, archive/media/document
  conversion, and path/option/environment construction;
- template renderers, report/email/PDF generation, CMS/themes, and expression
  languages where data might become template source;
- deserialization, import/export, XML/object formats, sessions, queues, caches,
  RPC, and polymorphic/type-selected handlers;
- uploads, previews, metadata stripping, OCR/AV, extraction, transcoding,
  content sniffing, and nested/container formats;
- logging/configuration lookup, dynamic loaders, plugin systems, scripting,
  admin automation, CI/CD, webhooks, jobs, and deployment hooks;
- error, fallback, validation, parser-selection, and header/content-type paths
  that select a different consumer than the normal flow.

## Look Beyond Visible Fields

Headers and cookies are easy to overlook when mapping only forms, URLs, and
bodies. Treat transport metadata and round-tripped server-issued state as input
carriers too: signed sessions, callback/resume tokens, custom headers, and opaque
references may reach different consumers. Distinguish merely readable state from
modifications a server accepts. Trace nested encodings and the handler that later
reads the value; neither the carrier nor its apparent format determines the
primitive. Use `rce-deserialization` when object reconstruction is plausible;
header-driven parser/error paths may instead select another execution family.

## Lead Packet

Create one compact packet per distinct candidate:

```text
map evidence: route/flow/component/worker or technology fact
attacker-controlled producer or plausible control point
consumer and RCE primitive family
transforms and later consumers
trigger, privilege/sandbox, runtime/config/deployment prerequisites
why this is a lead, not proof
next precursor, mapping observation, or research question
```

## Procedure

1. Scan the application map by consumer family, not only endpoint names.
2. Trace each plausible producer to its immediate and later consumers.
3. Keep declared type, detected type, parser selection, execution identity, and
   prerequisite facts separate.
4. Preserve unproven but structurally plausible leads in the Hypothesis Ledger;
   promote observed application facts through MapStore.
5. Route a lead with a named, plausible source-to-executor question to
   `rce-validation` for a permitted precursor; otherwise clarify the primitive
   with `rce-exploration` first. Use
   `rce-lifecycle` for delayed consumers, or `rce-technology-research` when
   stack/advisory facts decide feasibility.

## Completion

Complete when every material application consumer family has either produced an
RCE lead packet, been explicitly considered inapplicable with a reopening
condition, or is recorded as an evidence gap.
