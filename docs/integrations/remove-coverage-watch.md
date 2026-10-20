# Remove mistaken Coverage watcher integration

- **Status:** accepted for beta integration
- **Owner:** Hermes; `t_47f31769`
- **Branch:** `fix/remove-coverage-watch-t47f31769`
- **Base commit:** `eb034af78363088f552a895b5a79f01987af57ad`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `fix/remove-coverage-watch-t47f31769`
- **Latest immutable recovery checkpoint:** `bd62838`
- **Feature implementation commit(s):** `bd62838`
- **Inspiration / canonical references:** direct user correction after release of `eb034af`.

## Intent

Remove the new agent-facing Coverage uptake watcher/automated backfill guidance from beta and Hoster. The user's watcher was Hermes observing the bounded backfill directly, not a new agent workflow. Preserve the prior worker-owned Coverage semantics from before the watcher release and retain legitimate campaign data (the single HubSpot mapping) unchanged.

## Implemented contract

Restore only the 10 changed code/skill/test paths to `5946cdb`, the parent of the erroneous watcher merge. No changes to `agents/surface_coverage.py`, earlier Bunny worker-owned handoff, or campaign data. No unattended watcher/service was ever installed.

## Evidence and review

- `git diff 5946cdb -- <10 touched paths>` is empty; compare after final edits.
- Tests: `python -m pytest -q tests/ agents/test_surface_coverage.py --ignore=tests/test_safety_incident.py`: 307 passed, 186 subtests passed; `git diff --quiet 5946cdb -- <10 touched paths>` confirmed exact pre-watch equivalence.
- Independent review: accepted. Reviewer confirmed all ten feature paths exactly match `5946cdb`, worker-owned Coverage remains, no live watcher references, focused suite 307 tests and 186 subtests.
- Hoster seed audit: exact `hubspot/web` surface `S-cf655cd5f7f9082f58568fb6` was read back as `no_assessment`, one question, zero assessment events; retained source file exists. It is not evidence of a completed review or fresh XSS adoption.
- Merge/ancestry evidence: feature based on fetched `origin/beta` `eb034af`.

## Blockers and deferred work

- Fresh worker-owned Coverage adoption remains unproven; existing processes may retain loaded instructions. Observe a natural fresh worker handoff manually, rather than installing a watcher.
- The historical Coverage inventory is sparse and a bulk backfill is not justified. No old rows will be rewritten in this rollback.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/remove-coverage-watch-t47f31769`
- **Latest immutable recovery checkpoint:** `bd62838`
- **Feature implementation commit(s):** `bd62838`
- **Exact resume point:** integrate reviewed rollback to beta and update selected Hoster runtime, then verify projected skills and preserved seed.
- **Working-tree state at handoff:** clean after decision commit.

## Decision gates

- **Integration gate:** empty path diff against pre-watch baseline, tests, independent review.
- **Activation / cohort gate:** selected Hoster runtime readback and seed preservation; no existing Pi session restart.
- **Promotion gate:** no main promotion.

## Decision record

- 2026-10-19 — user corrected watcher ownership; remove mistaken feature while preserving pre-existing Coverage and real Hoster evidence.
