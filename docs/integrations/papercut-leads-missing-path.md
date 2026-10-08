# MapStore leads search missing-path repair

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-leads-missing-path`
- **Base commit:** `134de76f99238a2302a10fe1cb115826e025f823`
- **Intended integration target:** `beta` (`origin/beta` fetched before branching)
- **Latest immutable recovery checkpoint:** `7a9bb2b`
- **Feature implementation commit(s):** `7a9bb2b`
- **Inspiration:** `PC-20261008-183811-1137674e`

## Intent and implemented contract

Keep `agents/leads.py search` listing all MapStore results even when an older lead lacks the optional `path` field. Preserve four tab-separated columns and ordinary path values. No data migration or target writes.

## Evidence and review

- RED: `python3 -m pytest -q agents/test_leads_cli.py -k legacy` failed with `KeyError: 'path'` at the search printer on the missing-path fixture.
- GREEN: `python -m pytest -q agents/test_leads_cli.py agents/test_map_store.py agents/test_leads_skill.py` → 75 passed in 214.76s. `git diff --check` clean.
- Independent review: pending.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

None expected. Integration requires focused tests and independent review. Runtime activation and stable promotion are not authorized by this task.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-leads-missing-path`
- **Latest immutable recovery checkpoint:** `7a9bb2b`
- **Feature implementation commit(s):** `7a9bb2b`
- **Exact resume point:** Independent review of `7a9bb2b` plus dossier follow-up, then merge to beta after integration checks.
- **Working-tree state at handoff:** implementation committed; this evidence update awaits a dossier-only commit.

## Decision gates

- **Integration gate:** focused tests green, independent review accepted, current beta reconciled.
- **Activation / cohort gate:** not part of task.
- **Promotion gate:** stable promotion requires separate authorization.

## Decision record

- 2026-10-08 — Current beta reproduces report with a missing-path query row; scoped search-printer repair and regression prepared.
