# MapStore long-title directory repair

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-mapstore-long-title`
- **Base commit:** `134de76f99238a2302a10fe1cb115826e025f823`
- **Intended integration target:** `beta` (`origin/beta` fetched before branching)
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration:** `PC-20261006-191235-11426a41`

## Intent and implemented contract

Bound the MapStore observation directory component for long titles to 200 ASCII bytes, leaving its normal short-title path unchanged. Truncated slugs retain a deterministic digest of the full normalized slug to distinguish common prefixes; existing collision suffix handling remains. Full titles remain in observation text and index; no migration, target action, or stable promotion.

## Evidence and review

- RED: `python3 -m pytest -q agents/test_map_store.py -k long_titles` failed with `OSError: [Errno 36] File name too long` from `_write_observation_unlocked`.
- GREEN: `python3 -m pytest -q agents/test_map_store.py -k 'long_titles or observation_slug_uses_title_and_run or write_url_scope or write_app_scope or write_surface_scope'` → 6 passed, 66 deselected.
- Independent review: pending.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

None expected. Integration requires independent review. Runtime activation and stable promotion are outside this task.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-mapstore-long-title`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** Independently review and commit decision; merge to beta after integrated checks.
- **Working-tree state at handoff:** intentionally uncommitted implementation and test before checkpoint.

## Decision gates

- **Integration gate:** focused tests green, independent review accepted, current beta reconciled.
- **Activation / cohort gate:** not part of task.
- **Promotion gate:** stable promotion requires separate authorization.

## Decision record

- 2026-10-08 — Current beta reproduces the long-title failure; bounded slug and distinct-prefix regression prepared.
