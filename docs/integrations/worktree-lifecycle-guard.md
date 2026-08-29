---
lifecycle: bbh-worktree/v1
task: branch-worktree-lifecycle-guard
branch: feat/worktree-lifecycle-guard
worktree: /home/ryushe/worktrees/bbh-worktree-lifecycle-guard
base: ac13c67bc96234ca5791399eb7b3dbf888fc6c7b
target: beta
status: active
opened_at: 2026-08-28T19:00:00Z
checkpoint: 35d2e063978038e51e2307b98dbd24443c0e6fe3
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
Initial checkpoint commits this dossier. Implementation and tests will follow in this worktree; beta activation is deferred until focused tests and hook/setup checks pass.
