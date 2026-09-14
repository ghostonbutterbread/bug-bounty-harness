# ScopeValidator annotation parsing integration dossier

- Status: implementation in progress; independent parent review required
- Owner: delegated Hermes bugfix agent; parent owns review and integration
- Branch: `fix/scope-validator-annotations`
- Worktree: `/home/ryushe/projects/bug_bounty_harness-scope-annotations`
- Base beta commit: `300f6f7fb33832c6fcb04c7afdf663c682e0da1c` (fetched origin/beta; local beta identical)
- Intended integration target: `beta`
- Inspiration: parent-provided seed `2026-09-14-scope-validator-annotation-parsing-bug.md`
- Latest immutable recovery checkpoint: first test-only checkpoint pending
- Feature implementation commits: none yet

## Intent and contract

Strip whitespace-delimited `::` prose at the file-loading boundary, for allows
and exclusions, before entry classification and existing URL hostname parsing.
Do not split IPv6 compression or literal `::` within URLs. Preserve existing URL
path matching semantics, wildcard semantics, and exclusion precedence. Offline
synthetic fixtures only; no runtime activation, recon, live requests, or pushes.

## Evidence and review

Initial RED: `python -m pytest agents/test_scope_validator.py -q` returned
4 failed, 1 passed: all annotated exact/wildcard exclusions returned False from
is_out_of_scope, despite exact/wildcard allows. Test-only checkpoint preserves
this reproducible failing state before the implementation.

The same faulty loader exists on stable `master` (local actual stable ref), but
repository rules and explicit user direction prohibit stable edits. Repair is
owned by beta's task branch; stable promotion and propagation to other agents'
active descendants are deferred to the parent. No identifiers or APIs change.

## Blockers and deferred work

- Independent review unavailable inside this child (no child spawning). Parent
  must inspect the actual diff and rerun focused tests before beta integration.
- Kanban CLI refuses delegated child contexts: `hermes kanban --board
  bug-bounty-harness list` exited 1, `delegate_task child contexts cannot mutate
  Kanban tasks or boards`. Parent must own the task/card; no guard bypass.
- Related ScopeManager exclusion loading defect is a separate task, not fixed.

## Resume and decision gates

Resume in the named feature worktree: implement the loader change, add portable
regressions, run the scope suite, checkpoint evidence, return to parent review.
Integration blocked until independent parent review and current-beta comparison.
Activation and stable promotion are not authorized. Retain this dossier on the
feature branch; remove it from beta during accepted integration cleanup.
