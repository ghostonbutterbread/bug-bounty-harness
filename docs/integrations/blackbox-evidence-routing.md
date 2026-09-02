# Black-box evidence routing integration dossier

- **Status:** feature
- **Owner:** Hermes Agent
- **Branch:** `feat/blackbox-evidence-routing`
- **Base commit:** `7e2efe78d651ff1041c762724121e50c0065d983`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-02
- **Owning feature branch/ref:** `feat/blackbox-evidence-routing`
- **Latest immutable recovery checkpoint:** `008da96dd007b29aa016f3093c8256080deef811`
- **Feature implementation commit(s):** `9dbbe1933438567ca5333a26386e5460a4aacb0a`, `934d20e84184a76941ca78456613ad453b5267b8`, `b5c63962ac3118f9ae24a63d0aa004acbe4a6d11`, `2644bc47f70fc68bf589751c240e857bf9915986`, `008da96dd007b29aa016f3093c8256080deef811`
- **Inspiration / canonical references:** `Shared/skill_seeds/2026-09-01-current-run-provenance-slices.md`; `Shared/skill_seeds/2026-09-01-lead-scoped-hypothesis-context.md`; Bounty Core `58a01ba6e68482dac00db480b86f47e0cdb595b2`; AI Policies `e936ab7a6f93746901fd99735d4bfc8f3751a05a`

## Intent

Add a bounded current-run provenance slice to shared MapStore facts so an active agent can recover only observations it authored in its current run without replacing normal shared factual queries or reading private peer hypotheses.

## Implemented contract

- `MapStore.query()` accepts additive exact `agent_id` and `run_id` filters.
- `map_store.py query` exposes those filters as `--agent-id` and `--run-id`.
- The filters compose with existing URL, surface, tag, status, time, limit, intent, and archived-state behavior; returned entries remain deterministically newest first.
- MapStore provenance remains factual and shared. This does not create a private MapStore store, a filesystem scan fallback, a broad historical preload, or any Hypothesis Ledger visibility bypass.
- BBH accepts an opaque `--lead-id` at creation, owner-only `release`, and explicit `lead-followup --lead-id` retrieval. Ordinary `list` remains owner/run private; the wrapper validates the exact public Lead card before Core retrieval and does not expose a broad peer queue.
- `leads.py create` retains legacy absolute-path stdout by default and emits the portable MapStore-relative Lead ID with `--relative-id`; `lead-followup` and `update-status` accept either exact form. Lead follow-up validates one public card, queries Core with both canonical forms, and deduplicates eligible context so existing absolute links and portable relative links interoperate; arbitrary, unrelated, or nonexistent IDs fail before Ledger retrieval.

## Evidence and review

- Tests and commands:
  - `PYTHONPATH=. uv run --with /home/ryushe/worktrees/bounty-core-lead-scoped-hypothesis-context --with pytest python -m pytest agents/test_map_store.py::TestMapStore::test_query_filters_to_exact_agent_and_run_provenance agents/test_map_store.py::TestMapStore::test_cli_query_filters_to_agent_and_run_provenance -q` — 2 passed.
  - `PYTHONPATH=. uv run --with /home/ryushe/worktrees/bounty-core-lead-scoped-hypothesis-context --with pytest python -m pytest agents/test_map_store.py agents/test_hypothesis_ledger.py agents/test_leads_cli.py -q` — 75 passed using Core `5089b104e7229cbf0f012875a4fbe3dc8d271af5`.
  - `git diff --check` — passed.
- Independent review: Core `5089b10` accepted. BBH review found equivalent absolute/relative Lead-ID lookups were not canonicalized through Core and the dossier was stale; this checkpoint adds bidirectional canonical lookup, regression coverage, and reconciled handoff metadata. Fresh BBH re-review remains required.
- Replay/cohort/fixture evidence: real temporary shared-storage fixture; no target activity.
- Merge/ancestry evidence: not yet performed.

## Blockers and deferred work

- **Missing test or evidence:** Explicit consumable/published Bounty Core revision and fresh BBH re-review of bidirectional Lead-ID compatibility.
- **Command / fixture / environment needed:** BBH isolated test environment with the accepted Core revision; use the current Core feature worktree only as an intermediate local package receipt until it is published.
- **Trigger to run it:** after fresh BBH review accepts this checkpoint and the reviewed Core revision is published through its integration lane.
- **Why it blocks integration, activation, or promotion:** BBH must not ship a feature whose Core dependency is only a local worktree, and compatibility claims need independent verification.
- **Next completion step / successor reference:** accept the fresh BBH review, publish/integrate Core, pin BBH to that immutable revision, and rerun the integration suite.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/blackbox-evidence-routing`
- **Latest immutable recovery checkpoint:** `008da96dd007b29aa016f3093c8256080deef811`
- **Feature implementation commit(s):** `9dbbe1933438567ca5333a26386e5460a4aacb0a`, `934d20e84184a76941ca78456613ad453b5267b8`, `b5c63962ac3118f9ae24a63d0aa004acbe4a6d11`, `2644bc47f70fc68bf589751c240e857bf9915986`, `008da96dd007b29aa016f3093c8256080deef811`
- **Exact resume point:** rerun BBH review for the bidirectional Lead-ID compatibility checkpoint, then publish/integrate the accepted Core revision and pin BBH before the final integration run.
- **Working-tree state at handoff:** bidirectional compatibility regression, wrapper repair, and dossier reconciliation pending commit.

## Decision gates

- **Integration gate:** feature code is committed, full affected suites pass in an isolated environment, explicit Core revision is selected, and independent review reconciles dossier/diff/test receipts.
- **Activation / cohort gate:** no runtime activation in this slice.
- **Promotion gate:** merge only into clean current `beta` through normal reviewed branch lifecycle; never directly into `main`.

## Decision record

- 2026-09-02 — created with current-run MapStore provenance query and CLI contract; 67 focused MapStore tests passed.
