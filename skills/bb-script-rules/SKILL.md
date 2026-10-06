---
name: bb-script-rules
description: Use when running a script during a BBH vulnerability hunt.
---

# BBH Script Rules

Load `/bb-script-rules` alongside the selected vulnerability-class skill when a
BBH hunt runs a script. Script output is non-exhaustive: it describes only what
the script checked. While a longer script runs, inspect the target's technology
stack for class-specific behavior its patterns may miss (for example,
framework-specific sinks, request flows, or custom validation paths). Reconcile
both before judging coverage.
