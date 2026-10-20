# Pull-based MapStore surface orientation integration dossier

- **Status:** feature
- **Owner:** Hermes bugfix
- **Branch:** `feat/mapstore-pull-surface-orientation`
- **Base commit:** `4cc4ae0c603edf94aaff6e98b5351d7681d55a93`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `feat/mapstore-pull-surface-orientation`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryu's request for on-location, optional MapStore recall without broad startup ingest or historical-lead drift.

## Intent

Let an agent entering a concrete URL, feature, component, or field retrieve a small factual map and inspect only one selected direction. Preserve independent exploration and privacy of peer hypotheses; do not populate a LaunchDarkly target corpus or impose a campaign-wide ingestion gate.

## Implemented contract

Application Behavior records accept optional location anchors and a one-line observed summary. `behavior query --location` exact-matches normalized anchors or behavior name/ID; `--url` remains exact. CLI query defaults to ten and reports truncation; legacy `--json` remains a list. `behavior show --id` returns only that behavior and linked observation lifecycle statuses, with missing evidence flagged. Existing URL/kind/tag queries and behavior records remain readable. Guidance directs agents to verify current edges, explore beyond the map, and distinguish lifecycle status from test coverage. Tested conclusions stay in MapStore observations linked to canonical Attempts, not duplicated into Behavior metadata.

## Evidence and review

- Tests and commands: baseline `python -m pytest agents/test_map_store.py -q` 74 passed; modified suite to rerun after final edit. `git diff --check` clean before final test.
- Independent review: pending.
- Replay/cohort/fixture evidence: fixture-backed location isolation, CLI bounds, exact drill-down, legacy CLI tests.
- Merge/ancestry evidence: pending fresh beta fetch.

## Blockers and deferred work

- No target-specific backfill in this change. Existing records lacking anchors remain queryable by exact URL/kind/name; component lookup needs evidence-backed anchors written by a future mapping run. Do not claim the LaunchDarkly map is populated or a runtime agent has used this feature.
- Runtime activation requires selected beta source/projection verification after integration; no live hunt is part of this feature.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/mapstore-pull-surface-orientation`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** final test, independent diff review, integration decision.
- **Working-tree state at handoff:** intentionally uncommitted until final suite and initial checkpoint.

## Decision gates

- **Integration gate:** focused tests and independent review against current `origin/beta`.
- **Activation / cohort gate:** explicit runtime projection and a fresh worker read; beta merge alone is not activation.
- **Promotion gate:** stable only on separate owner instruction.

## Decision record

- 2026-10-19 — feature created from fetched beta; bounded orientation and exact drill-down implemented.
