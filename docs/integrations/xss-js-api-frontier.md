# XSS JS/API frontier integration dossier

- **Status:** feature
- **Owner:** Hermes (Ryushe XSS follow-up)
- **Branch:** `fix/xss-js-api-frontier`
- **Base commit:** `95c0736` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-22
- **Owning feature branch/ref:** `fix/xss-js-api-frontier`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** `skills/xss/SKILL.md`, `skills/xss/references/source-acquisition.md`, `skills/js-pull/SKILL.md`, `skills/parameter-mining/SKILL.md`, `skills/api-surface-mapping/SKILL.md`, `skills/bounty-tools/SKILL.md`

## Intent

Make XSS breadth acquisition decisions predictable: missing usable JS switches to JS pull; absent selected-flow API map or relevant JS-aware Katana crawl triggers bounded scoped endpoint acquisition; parameter mining expands input names and route/field context when the existing pool cannot answer the selected flow. Keep active warm/hot paths moving and avoid treating crawler output as proven operations.

## Implemented contract

The XSS router lists three checks; source-acquisition owns the Katana reuse/fetch, safety and provenance boundary. Katana `-jc` is documented by ProjectDiscovery as JS parsing/crawling; its installed version help must be checked. No runnable wrapper or new schema is introduced. `api-surface-mapping` owns the operation graph, `bounty-tools` owns tool runs, `parameter-mining` owns source-attributed field extraction.

## Evidence and review

- `python3 -m pytest -q agents/test_xss_skill_clarity.py`: 8 passed.
- `git diff --check`: clean.
- Independent review of `f70dba3` requested correction: existing relevant crawl with incomplete map must be reconciled, not rerun; map adequacy must be selected-cluster-based. Both corrected in working tree; re-review pending.
- Bounded broad suite `python3 -m pytest -q agents/test_xss_skill_clarity.py tests --tb=no`: 317 passed, 1 skipped, 18 failed (safety incident CLI requires checkout-local `.venv`, unrelated `stack-to-program` index/launcher and `upload-surface` assertion). No changed XSS test failed; not a green receipt. Root `python3 -m pytest -q` previously failed collection on missing `bac_checks`.
- Alignment: universal live-testing and BBH entry unchanged; XSS owns class-specific checkpoint and points to owners for acquisition and operation interpretation.

## Blockers and deferred work

- Katana is absent from this local host; no live crawler run is claimed. A fresh XSS agent trial on an authorized fixture is not provided by text tests.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/xss-js-api-frontier`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** run validation and independent review; then integrate beta if accepted.
- **Working-tree state at handoff:** intentionally uncommitted during implementation.

## Decision gates

- **Integration gate:** focused tests, independent review, current fetched beta and clean integration checkout; disclose broad-suite failures.
- **Activation / cohort gate:** verify selected runtime skill source; Hoster separately.
- **Promotion gate:** no stable promotion requested.

## Decision record

- 2026-10-22 — created from fetched beta; XSS checkpoint and scoped Katana endpoint route drafted.
