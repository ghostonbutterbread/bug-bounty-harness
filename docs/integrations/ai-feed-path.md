# AI feed-path integration dossier

- **Status:** review-ready
- **Owner:** Hermes / t_7fcba937
- **Branch:** `docs/ai-feed-path`
- **Base commit:** `9d8d68c1051a893887859d92d02ecc600c3670a1`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `docs/ai-feed-path`
- **Latest immutable recovery checkpoint:** `c8f23fde40c602af364cba8fb10abc745063de19`
- **Feature implementation commit(s):** `fccd507ba954f1a1575b31bfa69b2c12d35abd68`, `c8f23fde40c602af364cba8fb10abc745063de19`
- **Inspiration / canonical references:** Discord thread 1559619608095232122; existing `/ai-tester`, `/map-store`, `/indirect-injection`.

## Intent

Make the source-to-reader AI feed path an explicit, reusable discovery step without adding storage schema or a new skill. Preserve existing live testing approval and evidence gates.

## Implemented contract

`/ai-tester` asks for actual agent capability evidence, examines the current app map and targeted MapStore facts, records writer/source/reader/trigger/consumer links and unknowns, tags observed writable facts `user-writable`, and tags `ai-feed-source` only after safe owned-role ingestion evidence. The marker is ingestion proof only, not a vulnerability claim. Downstream action remains subject to existing specialist and safety gates.

## Evidence and review

- Tests and commands: `git diff --check` clean; `python3 -m pytest agents/test_map_store.py -q` 72 passed; `slugify` preserves `user-writable` and `ai-feed-source`; `aiskillsync sync --profile security --skill ai-tester --dry-run -v` shows four correct projected links, no destination actions (source beta not yet updated).
- Independent review: first pass found a stale dossier and requested direct-echo clarification; both corrected for fresh review.
- Replay/cohort/fixture evidence: no live target probe in this guidance-only change.
- Merge/ancestry evidence: base `origin/beta` checked before branch creation.

## Blockers and deferred work

- No known blocker. Structured map relationships or automatic inference deferred unless an actual hunt demonstrates need; not part of this change.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/ai-feed-path`
- **Latest immutable recovery checkpoint:** `c8f23fde40c602af364cba8fb10abc745063de19`
- **Feature implementation commit(s):** `fccd507ba954f1a1575b31bfa69b2c12d35abd68`, `c8f23fde40c602af364cba8fb10abc745063de19`
- **Exact resume point:** obtain fresh independent review of the corrected tip, integrate into beta, then verify runtime projection.
- **Working-tree state at handoff:** clean after this dossier-only handoff commit.

## Decision gates

- **Integration gate:** focused checks and independent review, then beta merge.
- **Activation / cohort gate:** beta source and active linked skill resolve to reviewed guidance; no live test authorized by this change.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-13 — opened focused beta-based skill-guidance change.
- 2026-10-13 — first review required a commit-correct dossier and model-mediated ingestion distinction; corrected, awaiting fresh review.
