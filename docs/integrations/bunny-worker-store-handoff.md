# Bunny worker-owned store handoff — integration dossier

- **Status:** review-ready; final independent review accepted
- **Owner:** Hermes / Kanban `t_9502dac8`
- **Branch / owning ref:** `feat/bunny-worker-store-handoff-t9502dac8`
- **Worktree:** `/home/ryushe/worktrees/bbh-bunny-worker-store-handoff`
- **Base commit:** `9f56eb16d480eda212f7f76108a329d434aa9d9a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Latest immutable recovery checkpoint:** none yet (work in progress)
- **Implementation commits:** none yet
- **Inspiration:** LaunchDarkly coordinated worker evidence was transcribed into Coverage by the parent; worker-owned evidence and compact pointer handoffs reduce loss and duplication.

## Intent

Make workers write and verify their own deliberate Attempts, reusable facts, and narrowly evidenced Coverage; make the parent reconcile the class/lane frontier and steer, not duplicate transcripts. Do not touch a live campaign ledger or infer goal completion from a worker review.

## Implemented contract

Bunny packets supply program/family/lane, exact Attempt stream ID, leased surface/class, retained provenance, and conditional store triggers. Worker returns IDs, exact Coverage assessment event ID (or explicit no-assessment reason), observed versus interpreted result, open siblings and next discriminator. Coverage `assess` returns its history event ID and `history`/`verify --event-id` reads that exact event even after another assessment. Bound `/goal init` cannot be rebound or overwritten; existing unbound runs remain readable. Parent alone records explicit goal continuation.

## Evidence and review

- Focused suite: `python -m pytest -q tests/test_goal_router.py tests/test_bunny_skill.py tests/test_coverage_worker_receipt.py` — 34 passed.
- Broader suite: `python -m pytest -q tests/ --ignore=tests/test_safety_incident.py` — 278 passed, 174 subtests passed.
- Unfiltered `pytest` collects an unrelated root `test_catalog.py` without `bac_checks`; `tests/` alone has 15 launcher failures because this clean worktree lacks a local `.venv`. This limitation was present before this branch and is tracked as a papercut.
- Read-only Hoster LaunchDarkly baseline: live ledger present; 10 assessment history events, seven Attempt streams. No live campaign mutation.
- Initial independent review identified overwrite and missing exact assessment identity; both repaired with regression tests. Second review found failed `init` could leave an empty state; now atomically publishes complete state with no-overwrite semantics, and serialization/link-failure regression tests pass.
- Fresh final reviewer accepted the full diff, independently ran the focused suite (34 passed), broader suite (278 passed, 174 subtests), and `agents/test_surface_coverage.py` (24 passed, 12 subtests); injected `fsync` failure and concurrent-init race preserved one complete state. No material blocker.
- Merge/ancestry: feature HEAD equals fetched `origin/beta` before commit.

## Blockers and deferred work

- **Missing test/evidence:** checkout-local launcher suite under a populated `.venv`.
- **Command/environment:** `python -m pytest -q tests/test_safety_incident.py` in a BBH checkout with its configured `.venv`.
- **Trigger:** available installed project environment during beta/Hoster verification.
- **Impact:** unrelated launcher tests fail before reaching their client; targeted and other repository tests pass.
- **Next:** independent re-review, commit, merge to clean beta, run integrated tests, push beta, verify Hoster selected checkout and fresh skill resolver.

## Interruption / resume handoff

- **Owning ref:** `feat/bunny-worker-store-handoff-t9502dac8`
- **Latest recovery checkpoint:** none yet; commit before pausing.
- **Implementation commits:** none yet.
- **Exact resume point:** commit reviewed change, merge into clean beta, verify Hoster selected runtime.
- **Working tree:** reviewed implementation and tests ready for feature commit.

## Decision gates

- **Integration:** second reviewer accepts corrections, focused/broad green, clean beta target.
- **Activation:** beta publication followed by Hoster selected-source fast-forward, launcher/skill-path read-back and fresh consumer load; current running agents need a new turn/session and are not automatically retrofitted.
- **Promotion:** stable `main` is separate and not requested.

## Decision record

- 2026-10-19 — feature built; first and second review findings fixed; fresh final release review accepted.
