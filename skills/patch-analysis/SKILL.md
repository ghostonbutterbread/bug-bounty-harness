---
name: patch-analysis
description: Use when a patched release diff can narrow source analysis.
---

# Patch Analysis

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
