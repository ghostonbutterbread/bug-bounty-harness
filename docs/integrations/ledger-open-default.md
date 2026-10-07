# Ledger open-default routing integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch / owning ref:** `fix/ledger-open-default`
- **Base commit:** `52fc788c13f49be54746b44fd436cef1954f6e22`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Latest immutable recovery checkpoint:** `d0d8d8db28a6e3ad759679be06bd831034a41dcc` (implementation); reconciled tip `467af2c`.
- **Feature implementation commit(s):** `d0d8d8db28a6e3ad759679be06bd831034a41dcc`
- **Inspiration / canonical references:** BBH ledger skill, `agents/finding_visibility.py`, `agents/me_ledger.py`, manual-hunter submission guidance; Kanban `t_0b4cc1f7`.

## Intent

Keep submitted, duplicate, dropped, and confirmed findings out of default hunt-selection context while preserving explicit dedupe, status, retest, and historical review access. The beta CLI already filters its default list, but the runtime ledger skill only describes the raw canonical path and does not route list consumers to the filter.

## Implemented contract

The ledger skill now gives the default filtered list command and names explicit `--include-closed` access. Raw ledger/report bulk loading is not a default work-selection source. A new exact-FID `me_ledger.py get --fid` route returns one named entry without bulk-list exposure; `check` remains the file/class dedupe path. The list filter now excludes duplicate outcomes even if an older or inconsistent record still has `submission.state=not_submitted`. Operator-supplied submission status remains required. This is guidance, not a security access-control boundary against an agent able to read files.

## Evidence and review

- Tests: `python -m pytest -q agents/test_finding_visibility.py agents/test_me_ledger.py tests/test_ledger_skill_visibility.py` → 14 passed, 8 subtests passed; `git diff --check` clean; `python agents/me_ledger.py get --help` shows exact-FID command.
- Policy neighbors: `agents/index.md` says cold current surface/no broad prior findings; `skills/manual-hunter/SKILL.md` owns the submission record; `skills/ledger/SKILL.md` owns read guidance. No competing route found.
- Independent review: initial review found duplicate result without submitted state visible by default and a missing exact-FID route; both corrected and tested. Re-review approved reconciled diff `beta` `b4b8592` → feature `b578d36` with no blocking issues; reviewer reran 14 focused tests + 8 subtests and 20 adjacent ledger tests.
- **Merge/ancestry:** feature reconciled by merge with selected `beta` at `b4b8592` (unrelated SSRF guidance); focused tests passed again on reconciled tip `467af2c`.

## Blockers and deferred work

- Raw file access is not technically prevented by a filtered CLI. This task changes the default agent guidance, not filesystem permissions or arbitrary-agent access.
- Existing submission records require operator updates; unrecorded platform outcomes cannot be inferred.
- Activation requires beta integration and skill projection/read-back; until then the feature worktree is not runtime guidance.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/ledger-open-default`
- **Latest immutable recovery checkpoint:** `d0d8d8db28a6e3ad759679be06bd831034a41dcc` (implementation); reconciled tip `467af2c`.
- **Feature implementation commit(s):** `d0d8d8db28a6e3ad759679be06bd831034a41dcc`
- **Exact resume point:** merge reviewed feature into clean current `beta`; remove this temporary dossier on target; run integrated tests and verify projected skill, then push/read back `origin/beta`.
- **Working-tree state at handoff:** clean after the dossier checkpoint commit below.

## Decision gates

- **Integration gate:** focused tests, policy alignment, independent review, clean target and merged checks.
- **Activation / cohort gate:** read-back projected skill from selected beta source and a fresh consumer load.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-07 — created scoped routing refinement; initial review findings corrected; reconciled tip approved for beta integration. Raw ledger access remains possible and is deliberately not treated as an access-control boundary; no stable promotion requested.
