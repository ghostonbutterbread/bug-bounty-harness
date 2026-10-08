# MapStore leads search missing-path repair

- **Status:** review-ready
- **Owner:** Hermes bugfix
- **Branch / owning ref:** `fix/papercut-leads-missing-path`
- **Base commit:** `134de76f99238a2302a10fe1cb115826e025f823`
- **Intended integration target:** `beta` (`origin/beta` fetched before branching)
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration:** `PC-20261008-183811-1137674e`

## Intent and implemented contract

Keep `agents/leads.py search` listing all MapStore results even when an older lead lacks the optional `path` field. Preserve four tab-separated columns and ordinary path values. No data migration or target writes.

## Evidence and review

- RED: `python3 -m pytest -q agents/test_leads_cli.py -k legacy` failed with `KeyError: 'path'` at the search printer on the missing-path fixture.
- GREEN: `python3 -m pytest -q agents/test_leads_cli.py agents/test_leads_skill.py` → 4 passed; targeted MapStore writer/slug checks → 4 passed, 67 deselected. Full combined MapStore suite timed out after 180s at 61+ progress dots; it is broader than this printer-only change and has long-running cases.
- Independent review: pending.
- Merge / ancestry evidence: pending.

## Blockers and deferred work

None expected. Integration requires focused tests and independent review. Runtime activation and stable promotion are not authorized by this task.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/papercut-leads-missing-path`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** Run focused tests, independently review, record decision and commit; merge to beta after integration checks.
- **Working-tree state at handoff:** intentionally uncommitted implementation and test before checkpoint.

## Decision gates

- **Integration gate:** focused tests green, independent review accepted, current beta reconciled.
- **Activation / cohort gate:** not part of task.
- **Promotion gate:** stable promotion requires separate authorization.

## Decision record

- 2026-10-08 — Current beta reproduces report with a missing-path query row; scoped search-printer repair and regression prepared.
