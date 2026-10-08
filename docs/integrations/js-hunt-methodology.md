# JavaScript hunt methodology integration dossier

- **Status:** reviewed, authorized for beta integration and runtime skill sync
- **Owner:** Hermes
- **Branch:** `bug-bounty-harness/t_c21f1f78-implement-js-router-and-adaptive-js-hunt`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/.worktrees/t_c21f1f78`
- **Base commit:** `60a27386f531d32460e2175b017176e22de04597` (`origin/beta` after fetch)
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-08
- **Owning feature branch/ref:** `bug-bounty-harness/t_c21f1f78-implement-js-router-and-adaptive-js-hunt`
- **Latest immutable recovery checkpoint:** `0438b783757b7ac527e326df852cbe6d11fcb34e`
- **Feature implementation commit(s):** `7ee99f76508f70f1ef9781b6384a9f7d5b44987a`, `0438b783757b7ac527e326df852cbe6d11fcb34e`
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
- Independent review: a fresh read-only reviewer checked implementation commit `7ee99f76508f70f1ef9781b6384a9f7d5b44987a`, reran focused 10/10 and suite excluding unrelated baseline 205 passed/1 skipped. The initial dossier/registry blockers were corrected in `0438b783757b7ac527e326df852cbe6d11fcb34e`; independent re-review ACCEPTED exact tip `fa751cf4bcba6849a9fe056e192f5c6682bdd7f2` with no new material findings, focused 10/10 and 205 passed/1 skipped plus 167 subtests on the bounded suite.
- Replay/cohort/fixture evidence: offline source-only examples; no live target action.
- Merge/ancestry evidence: fetched `origin/beta` `1c48ae7c30a2f21370befcbd60284c1c4f01ba41` after the source-map accounting repair. An isolated detached no-commit merge had no conflict; with the branch-local dossier excluded, its staged code tree was `5731562baeab28e6f01c1925f8fa78570943d5eb`. On that combined tree `python3 -m pytest tests -q --ignore=tests/test_hoster_script_authority.py` returned 205 passed/1 skipped/167 subtests; `python3 -m pytest agents/test_js_analyzer.py -q` returned 189 passed. Preflight was aborted and its worktree removed, not integrated. Re-fetch and repeat against the final beta ref before merging.

## Blockers and deferred work

The unfiltered suite's Hoster guidance assertion is a known unrelated
baseline failure. Do not change protected `AGENTS.md` or unrelated tests on
this feature. A separate owner should reconcile the guidance/test and rerun
`python3 -m pytest tests/test_hoster_script_authority.py -q` before claiming
the **whole** suite passes. Skill projection/sync is authorized, but no
unrelated process restart or main promotion is part of this task.

Task `t_4f42599d` finished its master→beta history reconciliation at
`a797adee748e17f2bbfb517b7cf385eb281a71b6`. Ryushe subsequently
authorized this feature's merge, push, and skill sync. Re-fetch and test against
the current beta before publication; this authorization is not main promotion.

## Interruption / resume handoff

- **Owning feature branch/ref:** `bug-bounty-harness/t_c21f1f78-implement-js-router-and-adaptive-js-hunt`
- **Latest immutable recovery checkpoint:** `0438b783757b7ac527e326df852cbe6d11fcb34e` (includes registry correction; branch tip has a later dossier-only commit)
- **Feature implementation commit(s):** `7ee99f76508f70f1ef9781b6384a9f7d5b44987a`, `0438b783757b7ac527e326df852cbe6d11fcb34e`
- **Exact resume point:** fetch final `origin/beta`, preflight from a clean beta
  checkout with this dossier excluded, rerun focused and bounded full tests,
  verify the staged code tree, then merge/push from that beta worktree. Inspect
  configured skill projections and dry-run before sync; verify each selected
  runtime after applying. Stable promotion is not authorized here.
- **Working-tree state at handoff:** clean after dossier-only commit.

## Decision gates

- **Integration gate:** focused and full isolated tests, independent review, clean current beta integration tree.
- **Activation / cohort gate:** user authorized skill sync in this task; verify
  the selected beta checkout and projection per destination before calling it
  active, and do not restart unrelated running sessions.
- **Promotion gate:** main only on explicit user direction.

## Decision record

- 2026-10-07 — created beta-based scoped feature after user approval.
- 2026-10-07 — independent review of the first implementation commit held integration for two handoff/discoverability corrections; corrected branch awaits re-review.
- 2026-10-07 — re-review accepted corrected tip; isolated beta `1c48ae7` preflight passed. Integration deferred to avoid racing the active master→beta reconciliation owner.
- 2026-10-08 — parent reconciliation completed at beta `a797ade`; user authorized merge, push, and skill sync; integration and runtime receipts pending.
