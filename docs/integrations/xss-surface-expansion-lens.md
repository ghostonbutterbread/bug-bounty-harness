# Optional surface expansion integration dossier

- **Status:** review-ready
- **Owner:** Hermes (Ryushe correction)
- **Branch:** `docs/xss-surface-expansion-lens`
- **Base commit:** `c42a793` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-22
- **Owning feature branch/ref:** `docs/xss-surface-expansion-lens`
- **Latest immutable recovery checkpoint:** `95d8dd1`
- **Feature implementation commit(s):** `27d4625`, `7f01b24`, `95d8dd1`
- **Inspiration / canonical references:** `skills/xss/SKILL.md`, `skills/xss/references/source-acquisition.md`, `skills/jsluice/SKILL.md`, `skills/focused-recon/SKILL.md`, `skills/hypothesis-expansion-policy/SKILL.md`

## Intent

Undo the overprescribed XSS acquisition checkpoint. Provide a small cross-class menu of ways to find new surface rather than mandatory JS/parameter/API tool passes. Distinguish offline JS URL extraction from Katana `-jc` live crawling; no crawler should start merely to parse retained local JS.

## Implemented contract

XSS entry links `surface-expansion` only when looking for a new source/writer/consumer. New skill gives consumer, parameter, JS endpoint, new JS and scoped app/host directions; tool owners retain commands, scope, evidence and proof. Prior XSS checkpoint and Katana crawl section are removed. Existing browser/JS source-acquisition guidance remains conditional and does not become a startup gate.

## Evidence and review

- `python3 -m pytest -q agents/test_xss_skill_clarity.py`: 7 passed.
- `git diff --check`: clean.
- Independent review of `27d4625`: changes requested because broad XSS and browser-mediated paragraphs still mandated JS acquisition. Corrected in `7f01b24`; re-review found one remaining unconditional `js` table route, corrected in `95d8dd1`. Final independent re-review accepted: no mandatory startup JS acquisition remains.
- Bounded broad suite `python3 -m pytest -q agents/test_xss_skill_clarity.py tests --tb=no`: 316 passed, 1 skipped, 18 unrelated failures (safety incident CLI missing checkout-local `.venv`, stack-to-program index/launcher, upload-surface phrase); no green receipt. Root `python3 -m pytest -q` previously failed collection on missing `bac_checks`.
- Alignment: `js`/`js-pull` own inventory, `jsluice` owns offline URL extraction, `parameter-mining` fields, `api-surface-mapping` operation context, `focused-recon` corpus prioritization, and `hypothesis-expansion-policy` mechanism continuation. New skill owns only cross-class new-surface idea selection.

## Blockers and deferred work

- New skill projection must be verified for intended local runtime; Hoster separately. A live hunter behavior trial is not provided by text tests.

## Interruption / resume handoff

- **Owning feature branch/ref:** `docs/xss-surface-expansion-lens`
- **Latest immutable recovery checkpoint:** `95d8dd1`
- **Feature implementation commit(s):** `27d4625`, `7f01b24`, `95d8dd1`
- **Exact resume point:** integrate reviewed feature into fetched beta, test, and verify new skill projection.
- **Working-tree state at handoff:** clean after this dossier decision commit.

## Decision gates

- **Integration gate:** accepted independent re-review, focused validation, fetched beta and clean integration checkout; unrelated broad-suite failures disclosed. Approved for beta, not stable.
- **Activation / cohort gate:** confirm new skill resolves by name in bugfix profile, XSS link points to it; Hoster separately.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-22 — removed mandatory XSS breadth acquisition sequence in favor of optional cross-class lens.
- 2026-10-22 — accepted independent review after conditionalizing residual JS routes; beta integration approved.
