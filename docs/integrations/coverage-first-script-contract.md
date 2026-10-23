# Coverage-first script contract integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `docs/coverage-first-script-contract`
- **Base commit:** `720e3e2ca8960837d891c3bfdc44396c63c139ef`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Owning feature branch/ref:** `docs/coverage-first-script-contract`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryu's coverage-first script request; General Skills `script-manager`; AI Policies `resource-safety-policy`.

## Intent

Prevent BBH scripts from silently interpreting per-batch safety budgets as final corpus coverage, without removing network/rate safeguards.

## Implemented contract

`SCRIPT_POLICY.md` states complete input traversal, checkpoint/resume, explicit partial counts, configurable disk floor and per-attempt timeout distinction. This is guidance; existing scripts require separate tested repairs. Heuristic signals still do not prove semantic exhaustiveness.

## Evidence and review

- Tests and commands: `git diff --check` pending.
- Independent review: pending.
- Merge/ancestry evidence: based on fetched `origin/beta` at `720e3e2`.

## Blockers and deferred work

- **Missing test or evidence:** reviewer acceptance and final policy consistency checks.
- **Command / fixture / environment needed:** review changed policy against General Skills and AI Policies owners; `git diff --check`.
- **Trigger to run it:** before integration.
- **Why it blocks integration, activation, or promotion:** conflicting rules would cause different script behavior.
- **Next completion step / successor reference:** resolve findings; separate JS and recon implementation branches tracked on Kanban `t_b317a8e8`.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/coverage-first-script-contract`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** review policy, then commit and integrate to beta.
- **Working-tree state at handoff:** intentionally uncommitted pending review.

## Decision gates

- **Integration gate:** policy consistency review, clean diff and beta integration check.
- **Activation / cohort gate:** beta publication is not runtime activation.
- **Promotion gate:** explicit stable promotion only.

## Decision record

- 2026-10-23 — created policy branch from fetched beta; reviewer pending.
