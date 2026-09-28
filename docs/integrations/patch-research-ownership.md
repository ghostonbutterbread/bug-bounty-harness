# Patch research ownership integration dossier

- **Status:** feature
- **Owner:** Hermes Agent, Kanban `t_865b401d`
- **Branch / owning ref:** `feat/patch-research-local-sandbox`
- **Base commit:** `a7b783f616d60d83910705bba8f2c31f8c8dd0d8`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-28
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Inspiration:** Ryu requested BBH ownership and disposable local proof environments in Discord message `1554183415291707483`.

## Intent and implemented contract

Move the already-reviewed parallel CVE/diff research skill into BBH without changing the lane/reconciliation contract. Add an explicit locally isolated reproduction path for potentially destructive inputs, with task-owned Docker/VM resources, bounded network/privileges/host mounts, evidence capture, exact cleanup, and no implication of live-target permission. BBH remains the sole canonical source after the paired General Skills deletion.

## Evidence and review

- Tests/commands: `python3 -m pytest -q tests/test_vulnerability_patch_research_skill.py tests/test_patch_analysis_skill.py tests/test_goal_router.py agents/test_shared_skill_adoption.py` passed 17/17; `git diff --check` passed.
- Independent review: pending, including paired source deletion and profile projection.
- Replay/cohort/fixture: bounded local `python:3.11-alpine` container smoke with `--rm --pull=never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1`, benign tmpfs write, exact task label, then container/network/volume readback empty. No target traffic. Docker Compose plugin is absent on this host; guidance treats it as optional.
- Merge/ancestry: source branch from beta; verify before integration.

## Blockers and deferred work

- No known blocker. Runtime projection must wait until BOTH beta sources are reconciled; a same-name export from both is an intermediate migration state, not activation.
- Hoster activation is a separate later host-owned rollout, not assumed from this local source change.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/patch-research-local-sandbox`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Exact resume point:** implement skill + tests, run local proof smoke, obtain independent review, then merge/push beta before source deletion.
- **Working-tree state at handoff:** feature branch, expected task-owned edits.

## Decision gates

- **Integration:** independent review and tests for the receiving skill and exact cleanup contract.
- **Activation:** General Skills source deletion merged/pushed; profile-aware sync repoints existing managed links; fresh runtime resolves BBH source.
- **Promotion:** beta only; no main promotion or public PoC publication.

## Decision record

- 2026-09-28 — created for BBH receiving branch.
