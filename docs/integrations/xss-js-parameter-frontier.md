# XSS JS and parameter frontier integration dossier

- **Status:** review-ready
- **Owner:** Hermes (Ryushe request)
- **Branch:** `fix/xss-js-inventory-parameter-frontier`
- **Base commit:** `6ffdfee` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-22
- **Owning feature branch/ref:** `fix/xss-js-inventory-parameter-frontier`
- **Latest immutable recovery checkpoint:** `59ba2b5`
- **Feature implementation commit(s):** `bfc4693`, `59ba2b5`
- **Inspiration / canonical references:** XSS thread, `skills/xss/SKILL.md`, `skills/js-pull/SKILL.md`, `skills/parameter-mining/SKILL.md`

## Intent

An XSS breadth hunter could treat an absent JS corpus as optional and a large `params.txt` as sufficient parameter coverage. Make the JS acquisition prerequisite visible at entry and use source-attributed route/field coverage rather than archive size to decide whether to mine more parameters. Keep warm/hot path work unblocked and avoid declaring program-wide exhaustion.

## Implemented contract

The XSS router checks a usable scoped JS inventory with retained bodies and page/flow provenance before new breadth screening; missing inventory routes to `js` → `js-pull`, with explicit known-vector, inaccessible corpus, or hot-path exceptions and recorded gaps. The source-acquisition reference routes parameter mining on selected-flow gaps, shape/provenance and unreviewed frontier; Coverage comparison separates unexamined and reviewed paths. No downloader, schema, or global testing gate is added.

## Evidence and review

- Focused: `python3 -m pytest -q agents/test_xss_skill_clarity.py` → 7 passed.
- Independent review of `bfc4693`: changes requested (warm controlled paths also must continue; earlier unconditional parameter-mining route contradicted archive-first skip). Both corrected in `59ba2b5`; independent re-review accepted with no new blocker.
- Broad `python3 -m pytest -q` failed collection on pre-existing root `test_catalog.py` missing `bac_checks`.
- Bounded `python3 -m pytest -q agents/test_xss_skill_clarity.py tests` → 316 passed, 1 skipped, 18 failed (safety incident CLI requires checkout-local `.venv`, unrelated `stack-to-program` script-index/launcher assertions, and unrelated `upload-surface` phrase assertion). No failures in changed XSS guidance tests. `git diff --check` clean.
- Repository has no policy-lint helper; manually checked frontmatter and linked skill/reference names against current beta. Existing shared papercut records missing policy-lint guide.
- Alignment: universal live-testing and BBH entry card unchanged; `js-pull` owns acquisition, `parameter-mining` owns extraction, XSS owns class routing; no root-context change.

## Blockers and deferred work

- Broad suite still has unrelated collection/environment/existing assertions described above; not a green full-suite receipt. A real fresh XSS hunter trial remains an activation observation, not proof supplied by text tests.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/xss-js-inventory-parameter-frontier`
- **Latest immutable recovery checkpoint:** `59ba2b5`
- **Feature implementation commit(s):** `bfc4693`, `59ba2b5`
- **Exact resume point:** integrate into current beta, verify focused checks and selected runtime projection.
- **Working-tree state at handoff:** clean after this dossier decision commit.

## Decision gates

- **Integration gate:** accepted independent re-review, focused validation, broad suite failures scoped above, current fetched beta, clean integration checkout. Accepted for beta despite unrelated broad-suite failures; no stable promotion.
- **Activation / cohort gate:** verify selected runtime skill symlink resolves to integrated content; Hoster separately if intended.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-22 — created from fetched beta; routed acquisition and parameter-frontier decision in canonical XSS owner.
- 2026-10-22 — independent reviewer requested two corrections, then accepted both in re-review; beta integration approved with unrelated broad-suite failures disclosed.
