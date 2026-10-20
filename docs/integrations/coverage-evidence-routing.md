# Generic Coverage evidence guard integration

- **Status:** review pending
- **Owner:** Hermes; Kanban `t_65d21152`
- **Branch:** `fix/coverage-evidence-routing-t65d21152`
- **Base commit:** `6de012847458318726bed02deb10b99a627ede44`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `fix/coverage-evidence-routing-t65d21152`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** direct user instruction and read-only Hoster audit of recent Canva/LaunchDarkly runs.

## Intent

Coverage is a generic BBH capability, not contingent on Bunny or explicit goals. Make it available and expected at actual mapping/review pivots for every agent while retaining evidence-triggered, narrow writes; reject invalid fresh typed Attempt/MapStore links at the owning assessment writer. No watcher, cron, per-payload write, or historical campaign rewrite.

## Implemented contract

`SurfaceCoverageStore.assess` verifies each typed `attempt:`/`map:` reference against the resolved family/lane before updating current assessment/history, using the canonical read-only verifier; errors omit raw ref bodies and preserve the prior state. Legacy opaque refs remain accepted for compatibility and read as unverified. Generic `agents/index.md` routes all BBH agents to `/coverage` when a relevant semantic question is mapped or a scoped review is performed; no write for an Attempt alone or unvisited input. Coverage skill explains returned `attempt_id` versus display/media ID and exact stream.

## Evidence and review

- RED: new typed-ref regression initially failed for mismatched ID, wrong stream, malformed ID, missing map and showed unwanted history events.
- GREEN: focused suite `65 passed, 16 subtests`; broader `python -m pytest -q tests/ agents/test_surface_coverage.py agents/test_coverage_cli.py --ignore=tests/test_safety_incident.py`: 323 passed, 190 subtests passed. `git diff --check` clean.
- Independent review: pending.
- Historical cohort: Hoster Canva newly wrote 17 assessments with 25/25 typed refs missing; LaunchDarkly newer XSS run had 134 Attempt rows and no new Coverage event. Neither is silently rewritten.

## Blockers and deferred work

- Fresh natural worker adoption after Hoster activation is unproven; observe a new agent handoff and typed-link success. Existing Pi conversations may keep old instructions. Historical correction requires separately scoped evidence review; do not auto-promote or erase old assessments.
- Legacy opaque references cannot be verified. They stay accepted only for compatibility and cannot substantiate a verified conclusion by themselves.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/coverage-evidence-routing-t65d21152`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** independent review; reconcile findings, commit, integrate beta and update selected Hoster runtime; smoke rejected bad ref and accepted valid ref in disposable fixture without touching campaign state.
- **Working-tree state at handoff:** intentionally uncommitted during review; commit before pause.

## Decision gates

- **Integration gate:** focused/broad tests and independent review of writer behavior and generic route.
- **Activation / cohort gate:** selected Hoster runtime at reviewed beta SHA, projected skill/entry readback, disposable offline CLI verification; no live target traffic.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-19 — generic entry route and typed-link pre-write validation; no agent watcher/backfill workflow.
