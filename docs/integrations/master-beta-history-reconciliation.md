# Master-to-beta history reconciliation dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `chore/reconcile-master-history`
- **Worktree:** `/home/ryushe/worktrees/bbh-master-history-reconcile-20261007`
- **Base commit:** `60a27386f531d32460e2175b017176e22de04597`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `chore/reconcile-master-history`
- **Latest immutable recovery checkpoint:** `25dcaeeccdb7a719d497330cf3d8a19f9356ce23`
- **Feature implementation commit(s):** `25dcaeeccdb7a719d497330cf3d8a19f9356ce23` (merge commit)
- **Inspiration / canonical references:** user-authorized BBH stable-to-beta reconciliation; independent source-map/merge reviews.

## Intent

Make the published `master` history reachable from ongoing `beta` without losing beta's newer JS inventory behavior. This is a history merge, not a source-map reimplementation or stable release. The two master implementation commits are patch-equivalent to beta; master-only cleanup deletes two dossiers already absent on beta.

## Implemented contract

Merge `origin/master` into a beta-based feature worktree. The four overlapping files (`agents/js_analyzer.py`, `agents/test_js_analyzer.py`, `prompts/js-playbook.md`, `skills/js/SKILL.md`) retain beta's newer behavior. The resulting staged tree matches the beta tree plus this temporary dossier; no product path changes. Stable (`master`) promotion is separate and requires its own release gate.

## Evidence and review

- Tests and commands: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" python3 -m pytest -q -p no:cacheprovider agents/test_js_analyzer.py tests/test_jsluice_skill.py`: 187 passed. `... tests`: 201 passed, 1 skipped, 1 failed (`test_hoster_script_authority_uses_current_capability_not_machine_lists` expects obsolete AGENTS wording already absent on beta); full `tests agents` run timed out after 420 seconds without receipt. Stage tree equals beta + temporary dossier; `git diff --check` passed.
- Independent review: two read-only audits found no master-only source-map behavior and recommended beta semantic resolution; post-merge review pending.
- Merge/ancestry evidence: `origin/master` `5e7aecf` and `origin/beta` `60a2738` diverge 3/924; merge-tree reports four JS conflicts; `git cherry` marks first two master commits patch-equivalent.

## Blockers and deferred work

- **Missing evidence:** independent post-merge review and post-beta-integration check. The test-suite failure and full-suite timeout require separate stable-release disposition; full stable release compatibility check remains outside this branch.
- **Command / fixture:** focused JS tests from isolated worktree, broader beta suite, remote ancestry check after beta push.
- **Trigger:** after conflict resolution, before any beta integration or publication.
- **Why it blocks integration/promotion:** overlap could discard beta's newer fetch, packet and sink behavior.
- **Next completion step:** independently review feature merge `25dcaee`, then integrate into beta if approved; do not claim stable-release readiness.

## Interruption / resume handoff

- **Owning feature branch/ref:** `chore/reconcile-master-history`
- **Latest immutable recovery checkpoint:** `25dcaeeccdb7a719d497330cf3d8a19f9356ce23`
- **Feature implementation commit(s):** `25dcaeeccdb7a719d497330cf3d8a19f9356ce23` (merge commit)
- **Exact resume point:** independently review feature merge commit and tests; reconcile with fetched beta before integration.
- **Working-tree state at handoff:** clean after dossier checkpoint.

## Decision gates

- **Integration gate:** no lost intended behavior, passing tests, independent review, fetched current beta.
- **Activation gate:** none; runtime lane switch is not authorized by this history repair.
- **Promotion gate:** separate beta-to-master review and approval, with complete directional diff and runtime checks.

## Decision record

- 2026-10-07 — isolated beta-based feature worktree created for master history reconciliation.
- 2026-10-07 — merged master in feature branch with beta's four conflict files retained; staged product tree unchanged. Focused JS tests passed; broader tests include one pre-existing AGENTS wording failure and full-suite timeout.
- 2026-10-08 — recorded immutable merge checkpoint `25dcaee`; post-merge independent review pending.
