---
name: scripts
description: Use when running scripts during a BBH vulnerability hunt.
---

# Scripts

Load `/scripts` alongside the selected vulnerability-class skill when a BBH hunt
uses a script. Script output is non-exhaustive: it describes only what the
script checked. While a longer script runs, investigate application-specific
cases in that vulnerability class that its patterns may miss (for example,
framework-specific XSS sinks). Reconcile both before judging coverage.
