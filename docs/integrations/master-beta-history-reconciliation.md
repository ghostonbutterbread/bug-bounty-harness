# Master-to-beta history reconciliation dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `chore/reconcile-master-history`
- **Worktree:** `/home/ryushe/worktrees/bbh-master-history-reconcile-20261007`
- **Base commit:** `60a27386f531d32460e2175b017176e22de04597`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `chore/reconcile-master-history`
- **Latest immutable recovery checkpoint:** `a4202b8f7f0abd4ce79e1ad798221406c6329b82`
- **Feature implementation commit(s):** `25dcaeeccdb7a719d497330cf3d8a19f9356ce23` (master history), `a4202b8f7f0abd4ce79e1ad798221406c6329b82` (current beta sync)
- **Inspiration / canonical references:** user-authorized BBH stable-to-beta reconciliation; independent source-map/merge reviews.

## Intent

Make the published `master` history reachable from ongoing `beta` without losing beta's newer JS inventory behavior. This is a history merge, not a source-map reimplementation or stable release. The two master implementation commits are patch-equivalent to beta; master-only cleanup deletes two dossiers already absent on beta.

## Implemented contract

Merge `origin/master` into a beta-based feature worktree. The four overlapping files (`agents/js_analyzer.py`, `agents/test_js_analyzer.py`, `prompts/js-playbook.md`, `skills/js/SKILL.md`) retain beta's newer behavior. The resulting staged tree matches the beta tree plus this temporary dossier; no product path changes. Stable (`master`) promotion is separate and requires its own release gate.

## Evidence and review

- Tests and commands: Before current-beta sync, focused JS/skill tests 187 passed; launcher/dependency tests 16 passed; broader `tests` returned 201 passed, 1 skipped, 1 pre-existing AGENTS wording failure. Full `tests agents` timed out without receipt; browser-provisioner test file timed out. After clean merge of updated beta `1c48ae7`, `tests -k 'not hoster_script_authority_uses_current_capability_not_machine_lists'`: 201 passed, 1 skipped, 1 deselected; focused source-map tests 9 passed and JSLuice skill tests 2 passed. Combined JS run timed out after 120 seconds with no final receipt. All product files remain byte-for-byte identical to current beta; no new behavior is introduced by history reconciliation.
- Independent review: two read-only audits found no master-only source-map behavior; post-merge review approved history-only beta integration conditional on current-beta reconciliation, temporary dossier retirement, and explicit baseline-failure waiver. Refreshed-tip review pending.
- Merge/ancestry evidence: `origin/master` `5e7aecf` and initial beta `60a2738` diverged 3/924; `git cherry` marks first two master commits patch-equivalent. Beta advanced to `1c48ae7` with later source-map repair; feature merge `a4202b8` includes it cleanly. Diff from current beta is only this temporary dossier.

## Blockers and deferred work

- **Missing evidence:** refreshed-tip review and post-beta-integration test/read-back. The pre-existing test-suite failure and full-suite timeout explicitly block stable promotion but are waived for this tree-identical history-only beta integration, not for a release.
- **Command / fixture:** focused JS tests from isolated worktree, broader beta suite, remote ancestry check after beta push.
- **Trigger:** after conflict resolution, before any beta integration or publication.
- **Why it blocks integration/promotion:** overlap could discard beta's newer fetch, packet and sink behavior.
- **Next completion step:** review refreshed feature tip, then integrate into beta if approved; do not claim stable-release readiness.

## Interruption / resume handoff

- **Owning feature branch/ref:** `chore/reconcile-master-history`
- **Latest immutable recovery checkpoint:** `a4202b8f7f0abd4ce79e1ad798221406c6329b82`
- **Feature implementation commit(s):** `25dcaeeccdb7a719d497330cf3d8a19f9356ce23` (master history), `a4202b8f7f0abd4ce79e1ad798221406c6329b82` (current beta sync)
- **Exact resume point:** review refreshed feature tip and tests; fetch beta again before integration.
- **Working-tree state at handoff:** clean after dossier checkpoint.

## Decision gates

- **Integration gate:** no lost intended behavior, passing tests, independent review, fetched current beta.
- **Activation gate:** none; runtime lane switch is not authorized by this history repair.
- **Promotion gate:** separate beta-to-master review and approval, with complete directional diff and runtime checks.

## Decision record

- 2026-10-07 — isolated beta-based feature worktree created for master history reconciliation.
- 2026-10-07 — merged master in feature branch with beta's four conflict files retained; staged product tree unchanged. Focused JS tests passed; broader tests include one pre-existing AGENTS wording failure and full-suite timeout.
- 2026-10-08 — recorded immutable merge checkpoint `25dcaee`; post-merge independent review pending.
- 2026-10-08 — independent review accepted history-only beta integration with waiver limited to unchanged-tree baseline AGENTS test failure; merged advancing beta `1c48ae7` and reran focused and broad tests. Stable promotion remains blocked.
