---
name: patch-analysis
description: Use when a security patch, advisory, or release pair can guide source review.
---

# Patch Analysis

Use an upstream security fix as a focused starting point for offline source analysis. Diff the last vulnerable revision against the first patched revision, identify the exact behavioral invariant added by the fix, then trace equivalent paths and incomplete coverage. A patch diff creates hypotheses; it does not prove reachability, exploitability, or program impact.

## When to Use

- A security advisory, changelog, commit, or dependency update identifies a fix.
- Two release tags or source revisions bracket a suspected vulnerability.
- A target uses an affected open-source component, fork, plugin, or downstream integration.
- A prior code review needs a tight starting point rather than broad source scanning.

Do not use this to test an out-of-scope upstream project or as a substitute for source provenance and program authorization.

## Procedure

1. **Bracket the patch.** Record the repository URL plus immutable `old_rev` (last vulnerable) and `new_rev` (first patched) commits. Confirm `old_rev` is an ancestor of `new_rev`; otherwise identify the matching maintenance line before treating the diff as evidence.
2. **Diff the pair.** Inspect `git diff --find-renames --find-copies old_rev..new_rev` and account for changed source, tests, configuration, dependencies, and generated artifacts. Separate the likely security hunk from unrelated release work.
3. **State the invariant.** Write the former unsafe assumption, the check or behavior added by the patch, affected input/object state, and intended safe failure behavior. Cite file paths and symbols.
4. **Trace the old and new paths.** Follow callers, wrappers, serializers/parsers, asynchronous consumers, alternate routes, and duplicate implementations from the changed symbol to relevant sinks or guards. Distinguish confirmed control flow from a name-only match.
5. **Use tests as a boundary.** Diff the changed tests to identify the minimum triggering shape and intended behavior. Look for untested variants: alternate encodings/formats, object states, privilege contexts, error paths, and sibling APIs.
6. **Compare target code deliberately.** Establish the target component/version and its provenance. Search only its authorized source or locally acquired artifact for the old behavior and semantic equivalents; record exact matches separately from plausible equivalents.
7. **Hand off narrowly.** Create an evidence-backed hypothesis for the owning BBH skill or an offline test fixture. For any live validation, load the applicable live-testing and vulnerability-class skills and stop at the minimum proof needed.

## Commands

Run commands through `terminal` from the relevant source checkout:

```bash
# Confirm the revisions belong to one history line.
git merge-base --is-ancestor OLD_REV NEW_REV

# Establish changed-file scope, then inspect relevant hunks.
git diff --find-renames --find-copies --stat OLD_REV..NEW_REV
git diff --find-renames --find-copies --word-diff=plain OLD_REV..NEW_REV -- path/to/file

# Find the former behavior at the vulnerable revision.
git grep -n -E 'symbol_name|old_pattern' OLD_REV -- ':!vendor' ':!dist'
```

Use `search_files` and `read_file` for local source inspection. Avoid treating vendored, minified, or generated code as a complete explanation when upstream source is available.

## Evidence Record

Record:

- upstream repository and immutable revision pair;
- relevant changed files/symbols and the before/after invariant;
- target component/version provenance;
- input-to-guard/sink trace, alternate paths checked, and test gaps;
- result labelled **confirmed**, **disproven**, or **hypothesis**;
- scope and stop condition for any live handoff.

## Pitfalls

- Release diffs often contain unrelated refactors; prioritize the advisory context and regression test.
- Moved tags or unrelated branches can create a plausible but meaningless diff; preserve hashes and verify ancestry.
- One-line checks may depend on configuration or protocol changes elsewhere in the release.
- An old code pattern is not enough: prove its target version, reachability, and relevant configuration before claiming impact.

## Completion Criteria

Finish only when the revision pair and target provenance are recorded, the patch invariant is explicit, relevant changed files are accounted for, at least one caller and one alternate/sibling path have been checked, and any conclusion clearly separates evidence from open hypotheses.
