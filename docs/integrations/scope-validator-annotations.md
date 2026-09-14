# ScopeValidator annotation parsing integration dossier

- Status: locally verified; blocked on independent parent review/integration
- Owner: delegated Hermes bugfix agent; parent owns review and integration
- Branch: `fix/scope-validator-annotations`
- Worktree: `/home/ryushe/projects/bug_bounty_harness-scope-annotations`
- Base beta commit: `300f6f7fb33832c6fcb04c7afdf663c682e0da1c` (fetched origin/beta; local beta identical)
- Intended integration target: `beta`
- Inspiration: parent-provided seed `2026-09-14-scope-validator-annotation-parsing-bug.md`
- Latest immutable recovery checkpoint: `f15dbbdbc5fdb95bfe754c4a624480f757594dbf`
- Feature implementation commit: `f15dbbdbc5fdb95bfe754c4a624480f757594dbf`
- Test-only RED checkpoint: `e673f68`
- Current tip may include a subsequent dossier-only handoff commit; inspect it too.

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

GREEN after the three-line loader correction: same command returned 5 passed.
Expanded validator fixtures: 106 passed. Relevant offline suite:

```text
python -m pytest agents/test_scope_validator.py agents/test_scope_manager.py agents/test_scope_seed_files.py agents/test_scope_puller_seed_files.py -q
119 passed in 0.24s
```

Coverage: exact/wildcard denial over exact/wildcard allows; annotated and plain
allows/exclusions; URL hostname extraction and existing path constraints; IPv4,
IPv6 addresses/networks/bracketed URLs; literal URL `::`; space/tab annotations;
canonical/legacy and `excluded.txt` aliases; unaffected allowed sibling hosts.
All new fixtures isolate canonical and legacy paths under pytest tmp_path.
Import provenance resolved to this feature worktree's `agents/scope_validator.py`.
`git diff --check` passed. Re-fetched origin/beta before review handoff; unchanged
at the base SHA. Full repository suite not run: this slice uses the four inspected
offline scope test modules, not runtime/recon or service integration tests.

URL normalization remains owned by the existing URL matcher: a URL exclusion
matches its bare hostname and matching URL paths, not unrelated full URL paths.
Changing URL exclusions into host-wide full-URL bans would change the existing
contract and is intentionally not part of the annotation fix.

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

Resume in the named feature worktree: parent independently reviews the diff and
reruns the recorded offline scope suite, then decides beta integration. Working
tree will be clean at handoff; preserve the feature branch until review finishes.
Integration blocked until independent parent review and current-beta comparison.
Activation and stable promotion are not authorized. Retain this dossier on the
feature branch; remove it from beta during accepted integration cleanup.
