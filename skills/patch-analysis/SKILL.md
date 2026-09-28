---
name: patch-analysis
description: Use when a patched release diff can narrow source analysis.
---

# Patch Analysis

For an observed open-source component, version, and reachable feature, load
`vulnerability-patch-research` first: it owns the parallel known-CVE and
independent release-diff lanes, mechanism-level reconciliation, and local proof
stages. This skill is a focused exact-patch source-review technique within that
workflow, not a CVE-only trigger or replacement for the independent diff lane.

When analyzing source after an upstream security fix, diff the version that was patched against the version immediately before it. Use the exact changed code to narrow where to look next: the altered function, its callers, and equivalent code paths. The diff is a starting point for source review, not proof of a vulnerability.

## When to Use

- A security advisory, changelog, commit, or release identifies a fix.
- Two source revisions bracket the patch.
- Broad source analysis needs a concrete, security-relevant place to start.

## Procedure

1. Identify the last pre-patch revision and the first patched revision. Preserve their immutable commit IDs.
2. Diff the two revisions and isolate the actual security-relevant hunk from unrelated release changes.
3. State exactly what changed: the function/symbol, condition, parser, sanitizer, authorization check, or other behavior added, removed, or altered.
4. Start source analysis at that changed code. Inspect its callers, inputs, outputs, and semantically equivalent or duplicated paths for the same former assumption.
5. Use changed tests to understand the triggering case the patch covers and to guide nearby source review.

## Commands

Run commands through `terminal` from the source checkout:

```bash
# Review the exact release change.
git diff --find-renames --find-copies OLD_REV..NEW_REV

# Locate the changed symbol or prior pattern in the pre-patch tree.
git grep -n -E 'symbol_name|old_pattern' OLD_REV -- ':!vendor' ':!dist'
```

Use `search_files` and `read_file` to follow the changed symbol and its related paths.

## Completion Criteria

The analysis has an exact pre-/post-patch revision pair, the security-relevant change is identified, and source review has started from the changed code plus its relevant callers or equivalent paths.
