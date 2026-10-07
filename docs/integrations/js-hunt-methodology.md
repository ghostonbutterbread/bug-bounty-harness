# JavaScript hunt methodology integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_c21f1f78-implement-js-router-and-adaptive-js-hunt`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/.worktrees/t_c21f1f78`
- **Base commit:** `60a27386f531d32460e2175b017176e22de04597` (`origin/beta` after fetch)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Owning feature branch/ref:** `bug-bounty-harness/t_c21f1f78-implement-js-router-and-adaptive-js-hunt`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Discord #skills thread `1557540441786949763`; existing `skills/js/SKILL.md`, `prompts/js-playbook.md`, `skills/js/references/offline-fanout.md`.

## Intent

Make “hunt the JavaScript” an unambiguous adaptive workflow while retaining the existing inventory and provenance mechanics. `/js` routes explicit collection to `/js-pull` and broad or focused analysis to `/js-hunt`. A broad hunt maps application behavior, selects interesting flows, and produces evidence-backed specialist handoffs; narrow hunts bias that same workflow. Do not create a fixed per-vulnerability worker matrix or claim exhaustive coverage.

## Implemented contract

`skills/js/SKILL.md` routes broad and narrow hunt to `/js-hunt`, collection to
`/js-pull`, and legacy analyze/deep/offline-fanout/generate requests without
breaking their intent. `skills/js-pull/SKILL.md` reuses the existing inventory,
hash/provenance, source-map packet, and optional JSLuice flow. `skills/js-hunt/SKILL.md`
defines the broad behavior map, focus views, evidence-selected deep tracing,
cross-artifact correlation, and bounded lead/coverage handoff. The existing
playbook, offline fanout reference, and skill registry point to this ownership.
No new parser, downloader, live target test, or fixed class team was added.

## Evidence and review

- Tests and commands: TDD red `4 failed` before implementation; focused
  `python3 -m pytest tests/test_js_hunt_skill.py tests/test_jsluice_skill.py
  tests/test_business_logic_skill.py tests/test_credential_exposure_validation_skill.py -q`
  -> `10 passed`; broader focus including script policy -> `32 passed`;
  `python3 -m pytest tests -q --ignore=tests/test_hoster_script_authority.py`
  -> `205 passed, 1 skipped, 167 subtests passed`. `git diff --check` passed.
  Unfiltered suite -> `2 failed, 204 passed, 1 skipped`: the first failure
  was an exact-string JS handoff expectation and was fixed; the remaining
  `test_hoster_script_authority_uses_current_capability_not_machine_lists`
  expects `AGENTS.md` to include `Hoster is execution-only by default`, which
  is absent from unmodified `origin/beta` `AGENTS.md`. The test and guidance
  have no feature diff; this is a pre-existing mismatch, not waived correctness
  for the JS paths.
- Independent review: pending.
- Replay/cohort/fixture evidence: offline source-only examples; no live target action.
- Merge/ancestry evidence: pending.

## Blockers and deferred work

The unfiltered suite's Hoster guidance assertion is a known unrelated
baseline failure. Do not change protected `AGENTS.md` or unrelated tests on
this feature. A separate owner should reconcile the guidance/test and rerun
`python3 -m pytest tests/test_hoster_script_authority.py -q` before claiming
the **whole** suite passes. No beta runtime activation or main promotion is
part of this task.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_c21f1f78-implement-js-router-and-adaptive-js-hunt`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** commit verified JS guidance/test changes, request
  independent review of the exact feature range, reconcile findings, then
  decide beta integration against a clean current integration worktree.
- **Working-tree state at handoff:** uncommitted dossier during active implementation.

## Decision gates

- **Integration gate:** focused and full isolated tests, independent review, clean current beta integration tree.
- **Activation / cohort gate:** no runtime activation without separate decision.
- **Promotion gate:** main only on explicit user direction.

## Decision record

- 2026-10-07 — created beta-based scoped feature after user approval.
