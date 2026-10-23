---
name: bb-script-rules
description: Use when running or adapting a BBH script for target testing.
---

# BBH Script Rules

Load `/bb-script-rules` alongside the relevant BBH skill before running a
bug-bounty script to investigate a target. Run the documented script as a
baseline, and independently inspect the application's actual stack and flows.
While it runs (or after a short run), run deterministic, stack-specific checks
for behavior its generic patterns miss; write a task-local script when useful.
Reconcile both passes before judging coverage. A clean script result describes
only its checked inputs and rules, not exhaustion.

If the tailored check merits reuse, route its promotion through `script-manager`
and BBH `SCRIPT_POLICY.md`; that lifecycle does not delay the current hunt.
