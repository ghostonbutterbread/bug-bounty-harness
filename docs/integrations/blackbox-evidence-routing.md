# Black-box evidence routing integration dossier

- **Status:** feature
- **Owner:** Hermes Agent
- **Branch:** `feat/blackbox-evidence-routing`
- **Base commit:** `7e2efe78d651ff1041c762724121e50c0065d983`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-02
- **Owning feature branch/ref:** `feat/blackbox-evidence-routing`
- **Latest immutable recovery checkpoint:** `9dbbe1933438567ca5333a26386e5460a4aacb0a`
- **Feature implementation commit(s):** `9dbbe1933438567ca5333a26386e5460a4aacb0a`
- **Inspiration / canonical references:** `Shared/skill_seeds/2026-09-01-current-run-provenance-slices.md`; `Shared/skill_seeds/2026-09-01-lead-scoped-hypothesis-context.md`; Bounty Core `58a01ba6e68482dac00db480b86f47e0cdb595b2`

## Intent

Add a bounded current-run provenance slice to shared MapStore facts so an active agent can recover only observations it authored in its current run without replacing normal shared factual queries or reading private peer hypotheses.

## Implemented contract

- `MapStore.query()` accepts additive exact `agent_id` and `run_id` filters.
- `map_store.py query` exposes those filters as `--agent-id` and `--run-id`.
- The filters compose with existing URL, surface, tag, status, time, limit, intent, and archived-state behavior; returned entries remain deterministically newest first.
- MapStore provenance remains factual and shared. This does not create a private MapStore store, a filesystem scan fallback, a broad historical preload, or any Hypothesis Ledger visibility bypass.

## Evidence and review

- Tests and commands:
  - `PYTHONPATH=. uv run --with /home/ryushe/worktrees/bounty-core-lead-scoped-hypothesis-context --with pytest python -m pytest agents/test_map_store.py::TestMapStore::test_query_filters_to_exact_agent_and_run_provenance agents/test_map_store.py::TestMapStore::test_cli_query_filters_to_agent_and_run_provenance -q` — 2 passed.
  - `PYTHONPATH=. uv run --with /home/ryushe/worktrees/bounty-core-lead-scoped-hypothesis-context --with pytest python -m pytest agents/test_map_store.py -q` — 67 passed.
  - `git diff --check` — passed.
- Independent review: not yet performed.
- Replay/cohort/fixture evidence: real temporary shared-storage fixture; no target activity.
- Merge/ancestry evidence: not yet performed.

## Blockers and deferred work

- **Missing test or evidence:** BBH wrappers/Leads integration against Bounty Core lead-followup contract, canonical skill promotion, and independent review.
- **Command / fixture / environment needed:** BBH isolated test environment with an explicit committed Bounty Core revision; use the current Core feature worktree only as an intermediate local package receipt until a merged/published revision is selected.
- **Trigger to run it:** after the next wrapper/Leads implementation slice is committed.
- **Why it blocks integration, activation, or promotion:** this branch is a multi-slice feature; current-run MapStore filtering alone does not deliver the complete lead-scoped evidence-routing contract.
- **Next completion step / successor reference:** inspect and test BBH Hypothesis Ledger/Leads adapters for explicit `lead-followup --lead-id` consumption of Core `58a01ba6e68482dac00db480b86f47e0cdb595b2`.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/blackbox-evidence-routing`
- **Latest immutable recovery checkpoint:** `9dbbe1933438567ca5333a26386e5460a4aacb0a`
- **Feature implementation commit(s):** `9dbbe1933438567ca5333a26386e5460a4aacb0a`
- **Exact resume point:** inspect and test the lead-followup adapter as a separate TDD slice, then update this dossier with its immutable checkpoint.
- **Working-tree state at handoff:** dossier-only update pending commit.

## Decision gates

- **Integration gate:** feature code is committed, full affected suites pass in an isolated environment, explicit Core revision is selected, and independent review reconciles dossier/diff/test receipts.
- **Activation / cohort gate:** no runtime activation in this slice.
- **Promotion gate:** merge only into clean current `beta` through normal reviewed branch lifecycle; never directly into `main`.

## Decision record

- 2026-09-02 — created with current-run MapStore provenance query and CLI contract; 67 focused MapStore tests passed.
