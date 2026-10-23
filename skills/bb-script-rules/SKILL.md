---
name: bb-script-rules
description: Use when running or adapting a BBH script for target testing.
---

# BBH Script Rules

Load `/bb-script-rules` alongside the relevant BBH skill before running a
bug-bounty script to investigate a target. Reuse its documented scripts for
repeatable mechanics; their matches are seeds within declared inputs and rules,
not a census or proof of a source-to-impact chain. Zero matches and successful
execution do not establish exhaustion.

The agent owns the stack-specific investigation: identify the running framework
and build form, trace its actual inputs, transforms, consumers, defenses, and
impact, and design reproducible, context-matched checks for behavior generic
patterns miss. Do this while a longer script runs when useful; for a short run,
reconcile its result with direct evidence afterward. For example, a generic XSS
source/sink scan can seed review, while compiled-framework binding conventions
may require a separate deterministic pass to distinguish guarded, unguarded,
and inert writes. Preserve the checked corpus/rules and unexamined paths before
judging coverage; a script's clean result closes only its tested question.

Agents may create or extend a reusable BBH script for repeatable stack-specific
mechanics, rather than rerunning an undocumented hand pass. Load
`script-manager` and follow BBH `SCRIPT_POLICY.md` to discover the existing
owner, place and index the helper, preserve evidence/fixtures, check false
positives, and use the authorized review and integration path. A tailored
script may completely process a declared corpus, but that does not make its
security conclusions exhaustive. The agent retains semantic interpretation and
live validation under the selected skill's safety rules.
