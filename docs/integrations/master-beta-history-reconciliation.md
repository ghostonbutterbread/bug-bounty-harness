# Master-to-beta history reconciliation dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `chore/reconcile-master-history`
- **Worktree:** `/home/ryushe/worktrees/bbh-master-history-reconcile-20261007`
- **Base commit:** `60a27386f531d32460e2175b017176e22de04597`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `chore/reconcile-master-history`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** user-authorized BBH stable-to-beta reconciliation; independent source-map/merge reviews.

## Intent

Make the published `master` history reachable from ongoing `beta` without losing beta's newer JS inventory behavior. This is a history merge, not a source-map reimplementation or stable release. The two master implementation commits are patch-equivalent to beta; master-only cleanup deletes two dossiers already absent on beta.

## Implemented contract

Merge `origin/master` into a beta-based feature worktree. Four overlapping files (`agents/js_analyzer.py`, `agents/test_js_analyzer.py`, `prompts/js-playbook.md`, `skills/js/SKILL.md`) must retain beta's reviewed newer behavior. Verify the resolved tree against beta, run focused and broad checks, independently review, then integrate into a clean current beta worktree. Stable (`master`) promotion is separate and requires its own release gate.

## Evidence and review

- Tests and commands: pending merged-tree focused/full tests.
- Independent review: two read-only audits found no master-only source-map behavior and recommended beta semantic resolution; post-merge review pending.
- Merge/ancestry evidence: `origin/master` `5e7aecf` and `origin/beta` `60a2738` diverge 3/924; merge-tree reports four JS conflicts; `git cherry` marks first two master commits patch-equivalent.

## Blockers and deferred work

- **Missing evidence:** post-merge test receipt and independent review; full stable release compatibility check remains outside this branch.
- **Command / fixture:** focused JS tests from isolated worktree, broader beta suite, remote ancestry check after beta push.
- **Trigger:** after conflict resolution, before any beta integration or publication.
- **Why it blocks integration/promotion:** overlap could discard beta's newer fetch, packet and sink behavior.
- **Next completion step:** perform non-committing merge on this branch and inspect conflicts.

## Interruption / resume handoff

- **Owning feature branch/ref:** `chore/reconcile-master-history`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** merge master, preserve beta behavior, test, review, integrate into beta.
- **Working-tree state at handoff:** dossier only, no merge begun.

## Decision gates

- **Integration gate:** no lost intended behavior, passing tests, independent review, fetched current beta.
- **Activation gate:** none; runtime lane switch is not authorized by this history repair.
- **Promotion gate:** separate beta-to-master review and approval, with complete directional diff and runtime checks.

## Decision record

- 2026-10-07 — isolated beta-based feature worktree created for master history reconciliation.
