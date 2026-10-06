---
name: bb-script-rules
description: Use when running a bug-bounty script to investigate a target in BBH.
---

# BBH Script Rules

Load `/bb-script-rules` alongside the relevant BBH skill before running a
bug-bounty script to investigate a target. Script output is non-exhaustive: it
describes only what the script checked. While a longer script runs, inspect the
target's technology stack for behavior its patterns may miss (for example,
framework-specific sinks, request flows, or custom validation paths). Reconcile
both before judging coverage.
