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

## Scripts map

- [Harness script index](../../scripts/README.md) — cross-skill helpers and
  links to each skill-owned script index. Choose the relevant specialist skill
  first; its own Scripts map leads to its helpers and downstream lane.
- `/bounty-tools` owns execution and artifact handling for external tools and
  reusable recon/fuzz helpers, not vulnerability proof.
