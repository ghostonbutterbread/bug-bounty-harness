# ScopeValidator annotation parsing integration dossier

- Status: independently reviewed and verified; integration blocked by parent Kanban runtime guard
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

## Parent review and remaining blocker

Parent independently inspected the production diff, tests, and owning matcher;
accepted the bounded whitespace-delimited annotation repair and preservation of
URL path/IPv6 contracts. Independently reran the four-module suite: **119 passed
in 0.22s**. `git diff --check` passed. Fresh `git fetch origin beta` confirmed
both beta and origin/beta remain at the recorded base.

Parent also attempted `hermes kanban --board bug-bounty-harness list`; it failed
with `delegate_task child contexts cannot mutate Kanban tasks or boards` even in
the parent continuation. This blocks the required tracker/integration workflow;
no environment-guard bypass attempted. Implementation is reviewed but unmerged.
Related ScopeManager exclusion loading remains a separate documented defect.

## Resume and decision gates

Recover from checkpoint `5dc0de1b7f7ca48b0b64e0177bf7c8d56d4ccb07` plus this
review-only follow-up commit on the named feature branch. Resume in a working
parent Kanban context (or obtain an explicit owner handoff decision), create or
claim the task, then fetch/reconcile beta and integrate the reviewed fix into a
clean beta worktree. Rerun the four-module suite on the integrated tree. Retain
the worktree and dossier until then; remove the dossier during accepted
integration cleanup. No push, activation, or stable promotion was performed.
