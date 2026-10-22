# Optional surface expansion integration dossier

- **Status:** feature
- **Owner:** Hermes (Ryushe correction)
- **Branch:** `docs/xss-surface-expansion-lens`
- **Base commit:** `c42a793` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-22
- **Owning feature branch/ref:** `docs/xss-surface-expansion-lens`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `skills/xss/SKILL.md`, `skills/xss/references/source-acquisition.md`, `skills/jsluice/SKILL.md`, `skills/focused-recon/SKILL.md`, `skills/hypothesis-expansion-policy/SKILL.md`

## Intent

Undo the overprescribed XSS acquisition checkpoint. Provide a small cross-class menu of ways to find new surface rather than mandatory JS/parameter/API tool passes. Distinguish offline JS URL extraction from Katana `-jc` live crawling; no crawler should start merely to parse retained local JS.

## Implemented contract

XSS entry links `surface-expansion` only when looking for a new source/writer/consumer. New skill gives consumer, parameter, JS endpoint, new JS and scoped app/host directions; tool owners retain commands, scope, evidence and proof. Prior XSS checkpoint and Katana crawl section are removed. Existing browser/JS source-acquisition guidance remains conditional and does not become a startup gate.

## Evidence and review

- `python3 -m pytest -q agents/test_xss_skill_clarity.py`: 7 passed.
- `git diff --check`: clean.
- Independent review: pending.
- Bounded broad suite `python3 -m pytest -q agents/test_xss_skill_clarity.py tests --tb=no`: 316 passed, 1 skipped, 18 unrelated failures (safety incident CLI missing checkout-local `.venv`, stack-to-program index/launcher, upload-surface phrase); no green receipt. Root `python3 -m pytest -q` previously failed collection on missing `bac_checks`.
- Alignment: `js`/`js-pull` own inventory, `jsluice` owns offline URL extraction, `parameter-mining` fields, `api-surface-mapping` operation context, `focused-recon` corpus prioritization, and `hypothesis-expansion-policy` mechanism continuation. New skill owns only cross-class new-surface idea selection.

## Blockers and deferred work

- New skill projection must be verified for intended local runtime; Hoster separately. A live hunter behavior trial is not provided by text tests.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-surface-expansion-lens`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** run tests/review, then integrate beta and project the new skill if accepted.
- **Working-tree state at handoff:** intentionally uncommitted during implementation.

## Decision gates

- **Integration gate:** focused validation, independent review, fetched beta and clean integration checkout; disclose broad-suite failures.
- **Activation / cohort gate:** confirm new skill resolves by name in bugfix profile, XSS link points to it; Hoster separately.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-22 — removed mandatory XSS breadth acquisition sequence in favor of optional cross-class lens.
