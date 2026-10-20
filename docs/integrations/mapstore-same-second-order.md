# MapStore same-second ordering integration dossier

- **Status:** reviewed; integration pending
- **Owner:** Hermes bugfix
- **Branch:** `fix/mapstore-same-second-order`
- **Base commit:** `ac8aad783ff10785f51448b13d6e0d8d03002c09`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-19
- **Owning feature branch/ref:** `fix/mapstore-same-second-order`
- **Latest immutable recovery checkpoint:** `2cdfa2fa0afe91884054986ead595c678dd1b1c9`
- **Feature implementation commit(s):** `2cdfa2fa0afe91884054986ead595c678dd1b1c9`
- **Inspiration / canonical references:** Hoster clean beta checkout focused MapStore suite failed twice when earlier and later observations shared a second-resolution timestamp.

## Intent

Return the latest observation first for same-URL writes sharing an index timestamp; preserve existing index format and all older sorting behavior. No target data or live traffic.

## Implemented contract

MapStore prepends new index entries before its stable descending timestamp sort, so same-timestamp writes appear latest first. No path, CLI, schema, or storage format changes.

## Evidence and review

- Tests and commands: red deterministic same-second test failed; green `python -m pytest agents/test_map_store.py -q` 78 passed; `git diff --check` clean.
- Independent review: no blocking code finding; independent focused suite 78 passed and diff check clean at `2cdfa2f`.
- Replay/cohort/fixture evidence: Hoster initial and repeat suite each 1 failed, 76 passed; failure returned earlier unlinked observation first. Regression freezes `iso_now` to the same second for two writes.
- Merge/ancestry evidence: beta contains original change; fresh fetch required before integration.

## Blockers and deferred work

- Hoster activation blocked until review, beta publication, clean checkout update, and remote 78-test verification. Dirty old checkout and live browser units remain untouched.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/mapstore-same-second-order`
- **Latest immutable recovery checkpoint:** `2cdfa2fa0afe91884054986ead595c678dd1b1c9` (dossier-only commit follows).
- **Feature implementation commit(s):** `2cdfa2fa0afe91884054986ead595c678dd1b1c9`.
- **Exact resume point:** independent review then beta integration and remote rollout.
- **Working-tree state at handoff:** clean after dossier-only commit.

## Decision gates

- **Integration gate:** independent review and focused suite.
- **Activation / cohort gate:** clean selected Hoster checkout tests and managed projection verification.
- **Promotion gate:** stable only on separate owner instruction.

## Decision record

- 2026-10-19 — isolated same-second failure during Hoster beta activation, fixed at owning MapStore index boundary.
- 2026-10-19 — independently reviewed with 78 passing focused tests; accepted for beta integration only.
