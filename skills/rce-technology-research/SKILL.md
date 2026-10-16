---
name: rce-technology-research
description: "Research an observed RCE stack into a test packet."
version: 0.1.0
author: Ryushe, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, rce, research, advisories, technology]
    related_skills: [rce, rce-exploration, safe-fetch]
---

# RCE Technology Research

Load when an observed framework, parser, serializer, converter, process API, or
vendor advisory can change the next RCE hypothesis. It produces a small,
source-backed packet; it does not treat a CVE or public exploit as target proof.

## When to Use

- An observed stack, parser, dependency, or advisory materially changes the next hypothesis.
- A version-only or public-report lead needs target-specific precondition analysis.

## Research Packet

```text
observed component and evidence
primary sources/advisories and affected/fixed range
actual input-to-sink mechanism
precondition matrix: runtime, package, config, topology, role, feature
execution and sandbox/privilege context
safe discriminating observation
false-positive and duplicate risks
```

## Procedure

1. Retrieve primary vendor, maintainer, or authoritative research sources with
   `safe-fetch`; preserve source URL and evidence artifact.
2. Separate documented vulnerability conditions from observed target facts.
3. Extract the mechanism and preconditions, not a payload. State unknowns.
4. Return one target-specific question to `rce-surface-mapping` or
   `rce-validation`; close version-only and advisory-only claims as exposure
   triage when preconditions are missing.

## Completion

A usable packet has a source-backed mechanism, affected/fixed range when known,
a target-evidence distinction, and one safe next question.
