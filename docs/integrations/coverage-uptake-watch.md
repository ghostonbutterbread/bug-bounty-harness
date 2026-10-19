# Coverage uptake watch integration dossier

- **Status:** feature; review findings repaired, re-review pending
- **Owner:** Hermes; Kanban `t_1dbc97ba`
- **Branch:** `feat/coverage-uptake-watch-t1dbc97ba`
- **Base commit:** `5946cdb61cfbacb1dc91ce152d153c116f62cee0`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `feat/coverage-uptake-watch-t1dbc97ba`
- **Latest immutable recovery checkpoint:** `7977c48`
- **Feature implementation commit(s):** `7977c48` (initial); follow-up review repairs pending commit
- **Inspiration / canonical references:** `skills/coverage/SKILL.md`, `skills/bunny-collaborative/SKILL.md`, `agents/surface_coverage.py`.

## Intent

Make sparse historical Coverage visible without equating Attempt counts with reviewed surfaces; give new Bunny/goal runs a cheap read-only uptake check, a bounded offline backfill packet, and frontier pointers. Never write synthetic assessment outcomes or scan targets as a consequence of watching.

## Implemented contract

`bbh agents/coverage.py watch` requires explicit program/family/lane and optionally one exact Attempt stream; it reads existing Coverage history and bounded Attempt streams, reports question/status/event counts, typed-link signals and source availability (not URL/JS review). The goal checkpoint can include a selected worker stream's uptake signal. Skill guidance routes a narrow evidence-only backfill agent, which registers mapped questions and assesses only when scoped evidence actually substantiates an assessment; parent verifies exact pointers. No automatic scheduler or bulk backfill.

## Evidence and review

- Tests and commands: `python -m pytest -q tests/ agents/test_surface_coverage.py agents/test_coverage_watch.py --ignore=tests/test_safety_incident.py`: 316 passed, 186 subtests passed after review repairs. `git diff --check` clean.
- Independent review: three initial findings on missing exact streams, unbounded history/directory enumeration, and stale current assessments after older mapper rediscovery. First re-review found a cross-class stale path: rediscovery updates surface identity shared across all classes. Backfill now skips any existing surface across classes; strong bounded-stop regression uses a bounded-reviewed question. Final re-review pending.
- Cohort evidence: read-only Hoster historical census: 88 lanes scanned; 5 with Coverage DB; 50 with Attempt streams, 45 without Coverage DB. This is historical inventory, not evidence of post-release adoption.
- Merge/ancestry evidence: base equals fetched `origin/beta` at work start.

## Blockers and deferred work

- **Missing evidence:** a fresh post-activation worker-written Coverage question and assessment with exact event and Attempt verification; old cohorts predate the worker-owned feature.
- **Environment/trigger:** new Bunny collaboration session on Hoster with selected runtime and a naturally justified mapping/review; observe exact stream and Coverage readback, without inventing a test.
- **Why:** activation can establish command availability and read-only watcher function; it cannot prove agents follow new instructions in already-running sessions.
- **Next completion step:** verify rollout on Hoster and monitor next fresh worker handoff.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/coverage-uptake-watch-t1dbc97ba`
- **Latest immutable recovery checkpoint:** `7977c48`
- **Feature implementation commit(s):** `7977c48` (initial); follow-up review repairs pending commit
- **Exact resume point:** reconcile independent review; run final tests; commit and integrate reviewed feature to `beta`; activate selected Hoster beta runtime and read back the watcher against an existing lane.
- **Working-tree state at handoff:** intentionally uncommitted during independent review; commit before any pause.

## Decision gates

- **Integration gate:** independent review and focused/broad tests, including read-only absence and linked/unlinked receipts.
- **Activation / cohort gate:** selected Hoster beta checkout and skill projection readback; historical census not a post-release adoption verdict.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-19 — chose an event-driven report-only watch and bounded agent backfill rather than unattended timer or inferred negative outcomes.
