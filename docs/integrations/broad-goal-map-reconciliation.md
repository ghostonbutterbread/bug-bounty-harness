# Broad-goal mapping reconciliation integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/broad-goal-map-reconciliation`
- **Base commit:** `ffc74f333b0a5a3d086c058aa87a77888b3d326a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-08
- **Owning feature branch/ref:** `docs/broad-goal-map-reconciliation`
- **Latest immutable recovery checkpoint:** `4f4a50c6b63930f33a7f7abb0591efe4ccb84d25`
- **Feature implementation commit(s):** `4f4a50c6b63930f33a7f7abb0591efe4ccb84d25`
- **Inspiration / canonical references:** broad-goal tunnel-vision review; `hunt-orchestration-policy`

## Intent

Make broad `/goal` runs retain orientation and reconcile unmapped surfaces before a broad negative or exhaustion conclusion, without delaying a strong current signal or forcing exhaustive mapping.

## Implemented contract

Broad plans load `hunt-orchestration-policy`, expose an opening contract that treats mapping as orientation, and expose a broad-only completion contract that asks whether more remains to map. Focused goals receive no completion contract. Missing auth/UI/MITM evidence remains a coverage gap, not exhaustion proof.

## Evidence and review

- Tests and commands: `uv run --with pytest python -m pytest tests/test_goal_router.py -q`; `python3 scripts/goal_router.py plan --program example --objective 'Find a new vulnerability'`; `python3 scripts/goal_router.py plan --program example --objective 'Find XSS in this comment preview' --url https://app.example/comments/preview --class xss`; `python3 -m compileall -q scripts/goal_router.py`; `git diff --check`.
- Independent review: approved; no blocking issues. Reviewer requested and this branch added explicit absence assertions for technology, continuation, and revalidation modes.
- Replay/cohort/fixture evidence: no live target interaction; deterministic planner fixtures only.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

- **Missing test or evidence:** beta integration validation.
- **Command / fixture / environment needed:** reviewer inspection plus beta branch policy/runtime validation after merge.
- **Trigger to run it:** before merge and activation.
- **Why it blocks integration, activation, or promotion:** policy change requires independent review and exact route verification.
- **Next completion step / successor reference:** review the feature diff; if accepted, update this dossier with the commit and integration decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/broad-goal-map-reconciliation`
- **Latest immutable recovery checkpoint:** `4f4a50c6b63930f33a7f7abb0591efe4ccb84d25`
- **Feature implementation commit(s):** `4f4a50c6b63930f33a7f7abb0591efe4ccb84d25`
- **Exact resume point:** await a deliberate beta-integration decision; preserve this dossier until the change is integrated or rejected.
- **Working-tree state at handoff:** clean after committing this dossier.

## Decision gates

- **Integration gate:** focused tests, independent review, explicit staged-diff inspection.
- **Activation / cohort gate:** beta skill/runtime projection must resolve the merged `bug-goals` source.
- **Promotion gate:** user-directed review and beta evidence; no main promotion implied.

## Decision record

- 2026-09-08 — implementation committed at `4f4a50c6b63930f33a7f7abb0591efe4ccb84d25`; independent review approved with non-blocking route-boundary test expansion applied.
