# Coverage uptake watch integration dossier

- **Status:** final review accepted; ready for beta integration
- **Owner:** Hermes; Kanban `t_1dbc97ba`
- **Branch:** `feat/coverage-uptake-watch-t1dbc97ba`
- **Base commit:** `5946cdb61cfbacb1dc91ce152d153c116f62cee0`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `feat/coverage-uptake-watch-t1dbc97ba`
- **Latest immutable recovery checkpoint:** `62ab102f59ca5fed57f220511650a44bbc6c2ec1`
- **Feature implementation commit(s):** `7977c48`, `2b3f240`, `62ab102`
- **Inspiration / canonical references:** `skills/coverage/SKILL.md`, `skills/bunny-collaborative/SKILL.md`, `agents/surface_coverage.py`.

## Intent

Make sparse historical Coverage visible without equating Attempt counts with reviewed surfaces; give new Bunny/goal runs a cheap read-only uptake check, a bounded offline backfill packet, and frontier pointers. Never write synthetic assessment outcomes or scan targets as a consequence of watching.

## Implemented contract

`bbh agents/coverage.py watch` requires explicit program/family/lane and optionally one exact Attempt stream; it reads existing Coverage history and bounded Attempt streams, reports question/status/event counts, typed-link signals and source availability (not URL/JS review). The goal checkpoint can include a selected worker stream's uptake signal. Skill guidance routes a narrow evidence-only backfill agent, which registers mapped questions and assesses only when scoped evidence actually substantiates an assessment; parent verifies exact pointers. No automatic scheduler or bulk backfill.

## Evidence and review

- Tests and commands: `python -m pytest -q tests/ agents/test_surface_coverage.py agents/test_coverage_watch.py --ignore=tests/test_safety_incident.py`: 316 passed, 186 subtests passed after review repairs. `git diff --check` clean.
- Independent review: accepted final beta code gate. Earlier missing-stream, unbounded enumeration, and historical remapping findings were corrected. Final reviewer reproduced the cross-class stale behavior, confirmed the all-class skip rule, and ran 57 focused tests/12 subtests and 316 broad tests/186 subtests.
- Cohort evidence: read-only Hoster historical census: 88 lanes scanned; 5 with Coverage DB; 50 with Attempt streams, 45 without Coverage DB. This is historical inventory, not evidence of post-release adoption.
- Merge/ancestry evidence: base equals fetched `origin/beta` at work start.

## Blockers and deferred work

- **Missing evidence:** a fresh post-activation worker-written Coverage question and assessment with exact event and Attempt verification; old cohorts predate the worker-owned feature.
- **Environment/trigger:** new Bunny collaboration session on Hoster with selected runtime and a naturally justified mapping/review; observe exact stream and Coverage readback, without inventing a test.
- **Why:** activation can establish command availability and read-only watcher function; it cannot prove agents follow new instructions in already-running sessions.
- **Next completion step:** verify rollout on Hoster and monitor next fresh worker handoff.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/coverage-uptake-watch-t1dbc97ba`
- **Latest immutable recovery checkpoint:** `62ab102f59ca5fed57f220511650a44bbc6c2ec1`
- **Feature implementation commit(s):** `7977c48`, `2b3f240`, `62ab102`
- **Exact resume point:** integrate reviewed feature into `beta`; activate selected Hoster beta runtime and read back watcher against an existing lane.
- **Working-tree state at handoff:** clean after dossier decision commit.

## Decision gates

- **Integration gate:** independent review and focused/broad tests, including read-only absence and linked/unlinked receipts.
- **Activation / cohort gate:** selected Hoster beta checkout and skill projection readback; historical census not a post-release adoption verdict.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-19 — chose an event-driven report-only watch and bounded agent backfill rather than unattended timer or inferred negative outcomes.
