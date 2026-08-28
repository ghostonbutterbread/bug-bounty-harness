# Goal-router defer MapStore integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `fix/goal-router-defer-mapstore`
- **Base commit:** `8796a55352cbd0a190216e70611332e8f7802e85`
- **Intended integration target:** `beta`
- **Last updated:** 2026-08-28
- **Owning feature branch/ref:** `fix/goal-router-defer-mapstore`
- **Latest immutable recovery checkpoint:** none yet — implementation and dossier pending first commit
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Discord thread 1542698142422536252; `skills/bug-goals/SKILL.md`

## Intent

Fresh broad, focused, and technology `/goal` routes must not preload historical MapStore context. MapStore remains an available retrieval capability, but a runner must first identify a concrete current surface and decision question before querying it. Explicit continuation and revalidation retain their historical-context behavior.

## Implemented contract

`goal_router.py` no longer includes `map-store` in the skill list for broad-program, focused-surface, or technology-review modes. Its emitted research contract requires a concrete current surface and decision question before MapStore retrieval and then restricts the use to answering that question. The canonical `bug-goals` skill mirrors that behavior. Tests assert deferred availability for fresh modes and retain continuation/revalidation coverage.

## Evidence and review

- Tests and commands: direct execution of all six `tests/test_goal_router.py` behavior tests with a temporary fixture; `python3 -m py_compile scripts/goal_router.py tests/test_goal_router.py`; `python3 scripts/goal_router.py plan --program example --objective 'Find a new vulnerability'`; `git diff --check`.
- Independent review: completed. One medium coverage finding identified missing assertions for fresh technology and historical continuation/revalidation modes; assertions were added and the direct behavior suite was rerun successfully.
- Replay/cohort/fixture evidence: no target interaction; the plan output is a local deterministic fixture.
- Merge/ancestry evidence: branch begins at beta commit `8796a55352cbd0a190216e70611332e8f7802e85`.

## Blockers and deferred work

- **Missing test or evidence:** `pytest` runner is unavailable in the active Hermes Python environment.
- **Command / fixture / environment needed:** a repository test environment with pytest installed.
- **Trigger to run it:** before a broader repository test suite is required; direct behavior tests already passed without pytest.
- **Why it blocks integration, activation, or promotion:** it does not block this focused router change because every test function was executed directly.
- **Next completion step / successor reference:** obtain independent diff review, commit, then merge to beta if accepted.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/goal-router-defer-mapstore`
- **Latest immutable recovery checkpoint:** none yet — commit next.
- **Feature implementation commit(s):** none yet.
- **Exact resume point:** review the working-tree diff, commit implementation, then update this dossier with the commit SHA.
- **Working-tree state at handoff:** intentionally uncommitted — initial implementation awaiting review.

## Decision gates

- **Integration gate:** tests, review, clean merge into current beta.
- **Activation / cohort gate:** no runtime activation; next `/goal` plan output must show MapStore as a capability but not an initially loaded skill.
- **Promotion gate:** explicit user-directed beta-to-main promotion only.

## Decision record

- 2026-08-28 — created and implemented deferred MapStore retrieval contract; local verification passed, pending review and first commit.
