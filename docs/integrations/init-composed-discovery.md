# Composed program initialization integration dossier

- **Status:** review-ready
- **Owner:** Hermes / Kanban `t_1205ee4c`
- **Branch:** `feat/init-composed-recon-js-api-params`
- **Base commit:** `dd45b128dd61e9a1df91345803cd9924ddb1fa70` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Owning feature branch/ref:** `feat/init-composed-recon-js-api-params`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Discord init discussion; `skills/recon/SKILL.md`, `scripts/program_init.py`, `/recon-corpus-write-policy`

## Intent

Make full initialization collect JS, API and parameters after the appropriate dependencies, with focused JS/API/params modes. Basic initialization remains unchanged. Recon Bus remains the canonical reusable surface corpus; the CLI must remain plan-only and cannot claim live collection.

## Implemented contract

`--mode full|js|api|params` emits mode-specific pending handoffs from saved scope. Full can run `/recon` and JS acquisition concurrently with a shared budget and incremental scope-validated discoveries; focused modes ensure recon before JS. Full API mapping waits for JS/Katana/docs but may proceed while broad recon runs; a final recon-to-API reconciliation waits for completed recon. Focused API waits for recon too; parameter mining consumes the reconciled API and docs. Each producer promotes scoped reusable surface records through Recon Bus at checkpoints. Recon Bus URL probes are part of the aggregate rate/destination budget, otherwise promotion is record-only. No live scanner or worker is launched by the initializer.

## Evidence and review

- Tests and commands: `python3 -m pytest tests/test_program_init.py tests/test_recon_bus.py -q` (51 passed after fixes), `git diff --check`, `python3 scripts/program_init.py --help`, `python3 scripts/recon_bus.py append --help`.
- Independent review: three concrete findings (broad recon gate, docs ordering, probe-rate accounting); patched and clean narrow re-review (20 focused tests, diff check and Recon Bus flags independently verified).
- Replay/cohort/fixture evidence: local mocked scope-pull tests exercise deterministic pending handoffs, idempotence, refresh and empty-scope rejection. No live target run requested.
- Merge/ancestry evidence: pending fetched-beta recheck.

## Blockers and deferred work

- No blockers for a plan-only initializer. Target-side execution requires a named program, current published scope/rules and aggregate rate authorization; that is not supplied by this repository change.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/init-composed-recon-js-api-params`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** Commit reviewed feature, recheck fetched beta, integrate into beta and verify projection.
- **Working-tree state at handoff:** intentionally uncommitted pending review/commit.

## Decision gates

- **Integration gate:** Focused tests and independent review passed; clean beta merge and integrated checks remain.
- **Activation / cohort gate:** Verify selected BBH runtime projection reads the integrated skill and CLI; no live program run without scope/rate approval.
- **Promotion gate:** No stable promotion implied.

## Decision record

- 2026-10-23 — created feature worktree from fetched beta; implemented dependency-aware plan and focused tests.
- 2026-10-23 — resolved three independent review findings; narrow re-review clean. Integrate only after fresh beta ancestry and integrated tests.
