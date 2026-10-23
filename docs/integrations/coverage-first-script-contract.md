# Coverage-first script contract integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `docs/coverage-first-script-contract`
- **Base commit:** `720e3e2ca8960837d891c3bfdc44396c63c139ef`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-23
- **Owning feature branch/ref:** `docs/coverage-first-script-contract`
- **Latest immutable recovery checkpoint:** `a0af5d3`
- **Feature implementation commit(s):** `e8eb746`, `a0af5d3`
- **Inspiration / canonical references:** Ryu's coverage-first script request; General Skills `script-manager`; AI Policies `resource-safety-policy`.

## Intent

Prevent BBH scripts from silently interpreting per-batch safety budgets as final corpus coverage, without removing network/rate safeguards.

## Implemented contract

`SCRIPT_POLICY.md` routes scoped discovery boundaries and partial-result handling to the shared `script-manager` contract, and applies BBH scope/rate safety. The 5 GiB default floor and per-attempt timeout distinction are owned by the referenced AI Policies `resource-safety-policy`, not repeated here. This is guidance; scripts require separate tested repairs. Heuristic signals still do not prove semantic exhaustiveness.

## Evidence and review

- Tests and commands: `git diff --check` passed after reviewer corrections.
- Independent review: first review's three findings corrected; independent re-review accepted the canonical-owner split with no concrete conflicts.
- Merge/ancestry evidence: based on fetched `origin/beta` at `720e3e2`; target still at that revision.

## Blockers and deferred work

- **Missing test or evidence:** active BBH script repair tests and runtime activation are separate.
- **Command / fixture / environment needed:** focused JS/recon tests on their feature branches; managed runtime read-back if activation requested.
- **Trigger to run it:** before claiming scripts repaired or runtime activated.
- **Why it blocks integration, activation, or promotion:** does not block policy integration, blocks those separate claims.
- **Next completion step / successor reference:** merge policy, remove dossier on beta; integrate JS and recon fixes only after their own review.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/coverage-first-script-contract`
- **Latest immutable recovery checkpoint:** `a0af5d3`
- **Feature implementation commit(s):** `e8eb746`, `a0af5d3`
- **Exact resume point:** commit this accepted-review handoff; integrate to beta and remove dossier there.
- **Working-tree state at handoff:** clean after this dossier commit.

## Decision gates

- **Integration gate:** policy consistency review, clean diff and beta integration check.
- **Activation / cohort gate:** beta publication is not runtime activation.
- **Promotion gate:** explicit stable promotion only.

## Decision record

- 2026-10-23 — created policy branch from fetched beta; reviewer pending.
