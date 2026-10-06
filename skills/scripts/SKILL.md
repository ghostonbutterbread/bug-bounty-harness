---
name: scripts
description: Use when running scripts during a BBH vulnerability hunt.
---

# Script-Assisted Hunting

Load `/scripts` alongside the selected vulnerability-class skill when a BBH hunt
uses a script for discovery or analysis. The selected skill and its script index
point to relevant commands; this skill governs how to use their evidence, not
script creation or maintenance. Routine tests, migrations, and operations are
not its trigger.

A script's output covers only the inputs and patterns it actually examined.
Treat hits as leads, and do not infer application-wide absence or completed
coverage from missing hits or an indexed script. A genuinely closed input and
complete check may support a narrower conclusion; name that boundary.

While a longer script handles its mechanical pass, use agent attention on the
application-specific questions in the selected vulnerability class that its
patterns may miss—for example, sinks or render consumers particular to the
observed framework. When it finishes, reconcile both streams, check the
script's actual coverage, and name remaining unexamined paths. For a short
script, do that reasoning during output review rather than inventing parallel
busywork.

The selected class skill still owns proof and prioritization. For live traffic,
program rules and `general-security-testing-policy` / `live-testing-policy`
retain scope, rate, ownership, and impact authority; `/scripts` grants no new
permission to test.
