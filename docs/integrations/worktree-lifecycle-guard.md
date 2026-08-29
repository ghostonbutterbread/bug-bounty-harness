---
lifecycle: bbh-worktree/v1
task: branch-worktree-lifecycle-guard
branch: feat/worktree-lifecycle-guard
worktree: /home/ryushe/worktrees/bbh-worktree-lifecycle-guard
base: ac13c67bc96234ca5791399eb7b3dbf888fc6c7b
target: beta
status: review-ready
opened_at: 2026-08-28T19:00:00Z
checkpoint: 646fd07
---

# Worktree lifecycle guard

## Intent
Prevent unmerged, forgotten BBH worktrees by making the existing branch-local integration dossier a required recoverable checkpoint and auditing actual Git worktree/ref state.

## Contract
- `open` creates a feature worktree from current `origin/beta` and a committed v1 dossier.
- `audit` classifies worktrees from Git plus dossier metadata; it never mutates.
- `retire` only removes clean branches proven contained or patch-equivalent to beta.
- The repository-local pre-push hook invokes branch-scoped strict audit.

## Evidence and resume

Verified from this worktree with the checkout runtime:

```text
15 tests passed: tests.test_worktree_lifecycle + tests.test_bbh_launcher
bash -n setup.sh
python3 scripts/worktree_lifecycle.py audit --strict --branch feat/worktree-lifecycle-guard
```

The AGENTS.md operational wording update was not applied because the protected-instruction-file approval did not arrive; the executable guard, hook, setup installation, and branch-local dossier are the implemented enforcement boundary.
