# Pull-based MapStore surface orientation integration dossier

- **Status:** reviewed; integration pending
- **Owner:** Hermes bugfix
- **Branch:** `feat/mapstore-pull-surface-orientation`
- **Base commit:** `4cc4ae0c603edf94aaff6e98b5351d7681d55a93`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `feat/mapstore-pull-surface-orientation`
- **Latest immutable recovery checkpoint:** `ad546f6eb79bb6538737ccf74d13708fff68bd1b`
- **Feature implementation commit(s):** `3e3cb951c5f31602adf0d59a7e950d04ca6ae64c`, `ad546f6eb79bb6538737ccf74d13708fff68bd1b`
- **Inspiration / canonical references:** Ryu's request for on-location, optional MapStore recall without broad startup ingest or historical-lead drift.

## Intent

Let an agent entering a concrete URL, feature, component, or field retrieve a small factual map and inspect one selected direction. Preserve independent exploration and privacy of peer hypotheses; do not populate a LaunchDarkly target corpus or impose a campaign-wide ingestion gate.

## Implemented contract

Application Behavior records accept optional location anchors and a one-line observed summary. `behavior query --location` exact-matches normalized anchors or behavior name/ID; `--url` remains exact. Location-only lookup refuses multi-host collisions and asks for an exact URL. Legacy behavior updates retain omitted anchors and summary. CLI query defaults to ten and reports truncation; legacy `--json` remains a list. `behavior show --id` returns one behavior and linked observation lifecycle statuses, with missing evidence flagged. Existing URL/kind/tag queries and behavior records remain readable. Guidance directs agents to verify current edges, explore beyond the map, and distinguish lifecycle status from test coverage. Tested conclusions stay in MapStore observations linked to canonical Attempts, not duplicated into Behavior metadata.

## Evidence and review

- Tests and commands: baseline `python -m pytest agents/test_map_store.py -q` 74 passed; initial implementation 76 passed; reviewer fixes 77 passed. `git diff --check` clean.
- Independent review: fresh reviewer requested changes at commit `3e3cb95`: cross-host anchor collision and legacy update metadata loss. Narrow independent re-review at `ad546f6` confirmed both fixes, reran 77 passing tests, `git diff --check` clean, and found no code blocker.
- Replay/cohort/fixture evidence: fixture-backed multi-host collision guard, legacy update retention, CLI bounds, exact drill-down and legacy CLI tests.
- Merge/ancestry evidence: pending fresh beta fetch.

## Blockers and deferred work

- No target-specific backfill in this change. Existing records lacking anchors remain queryable by exact URL/kind/name; component lookup needs evidence-backed anchors written by a future mapping run. Do not claim the LaunchDarkly map is populated or a runtime agent has used this feature.
- Runtime activation requires selected beta source/projection verification after integration; no live hunt is part of this feature.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/mapstore-pull-surface-orientation`
- **Latest immutable recovery checkpoint:** `ad546f6eb79bb6538737ccf74d13708fff68bd1b` (dossier-only commit may follow).
- **Feature implementation commit(s):** `3e3cb951c5f31602adf0d59a7e950d04ca6ae64c`, `ad546f6eb79bb6538737ccf74d13708fff68bd1b`.
- **Exact resume point:** fresh beta comparison, integration and activation boundary.
- **Working-tree state at handoff:** clean after the dossier-only commit.

## Decision gates

- **Integration gate:** focused tests and independent review against current `origin/beta`.
- **Activation / cohort gate:** explicit runtime projection and a fresh worker read; beta merge alone is not activation.
- **Promotion gate:** stable only on separate owner instruction.

## Decision record

- 2026-10-19 — feature created from fetched beta; bounded orientation and exact drill-down implemented.
- 2026-10-19 — independent review found two medium issues; fixed collision guard and legacy update retention; focused tests 77 passed, re-review pending.
- 2026-10-19 — narrow independent re-review confirmed both fixes with 77 passing tests; no code blocker; reviewed feature accepted for beta integration only.
