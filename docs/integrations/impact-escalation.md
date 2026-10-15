# Impact escalation integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/impact-escalation`
- **Base commit:** `ce0804a9853597e2e955df5f3914d98342a49fd0`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-14
- **Owning feature branch/ref:** `feat/impact-escalation`
- **Latest immutable recovery checkpoint:** `40cb870e630b0f9d379258534bf5b76bafb6eed1`
- **Feature implementation commit(s):** `90cefda2d06cbe9676b1c0f013211abe329e2a7f`, `40cb870e630b0f9d379258534bf5b76bafb6eed1`
- **Inspiration / canonical references:** Ryushe's Discord impact-escalation design; AI Policies `impact-fit-policy`, `assumption-testing`, and generic `impact-escalation` beta source.

## Intent

After prompt initial finding capture, explore defensible application-specific impact before a final Bunny report. Add XSS idea overlay and route it without turning the report writer into a live hunter. Keep existing live-testing, account, evidence, and reporting owners authoritative.

## Implemented contract

`agents/index.md`, `manual-hunter`, `security-reporting`, and `xss` route a captured FID to generic `impact-escalation`, then `xss-escalation` when confirmed XSS. The overlay prompts account control, durable auth, actions, data, and delivery; claimed UI/API guards route to `assumption-testing`. New effect proof remains in the same FID and `EVIDENCE.md`; final report remains Bunny's report-only job. No new target-testing authorization or ledger schema.

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_impact_escalation_routes.py tests/test_security_reporting_skill.py tests/test_reporting_markdown.py` (8 passed, 30 subtests); `git diff --check` passed. AI Policies lint and 43 tests passed separately.
- Independent review: completed-diff reviewer verified routing, safety, same-FID evidence, and the BBH maintainer pointer; it requested only correction of this dossier's stale clean/commit state. Narrow re-review of the correction pending.
- Replay/cohort/fixture evidence: offline agent evaluation of fictional stored XSS FID D17. It challenged a UI old-password claim against two routes: one enforced the guard, the other had a simulated owned-fixture email-state change. It did **not** claim ATO because login/recovery binding and fresh-session usability were unproven. Stale-auth token and viewer invite branches stayed negative. No real target traffic or effect.
- Merge/ancestry evidence: feature based on fetched `origin/beta` `ce0804a`.

## Blockers and deferred work

- **Missing test or evidence:** Narrow re-review of the dossier correction, plus current-beta reconciliation and post-merge tests. The prior protected-file gap is resolved in BBH `AGENTS.md`; no AI Policies `AGENTS.md` change is required.
- **Command / fixture / environment needed:** Review current feature commit and cumulative AI Policies policy diff; rerun the focused test commands after merging.
- **Trigger to run it:** BBH maintainer pointer has been written and its route regression passes.
- **Why it blocks integration, activation, or promotion:** Do not merge or sync an unreviewed final diff. Activation separately needs reviewed, published source and fresh runtime resolution.
- **Next completion step / successor reference:** Finish independent review, integrate into current `beta`, run checks, then verify remote and runtime source before claiming activation.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/impact-escalation`
- **Latest immutable recovery checkpoint:** `40cb870e630b0f9d379258534bf5b76bafb6eed1`
- **Feature implementation commit(s):** `90cefda2d06cbe9676b1c0f013211abe329e2a7f`, `40cb870e630b0f9d379258534bf5b76bafb6eed1`
- **Exact resume point:** review final diff; reconcile with current beta, merge, test, and verify source/runtime route.
- **Working-tree state at handoff:** clean after this dossier correction is committed; the AGENTS.md and route-test edits were committed in `40cb870`.

## Decision gates

- **Integration gate:** passing tests, independent review resolved, BBH `AGENTS.md` maintenance instruction present; reconcile current beta before merge.
- **Activation / cohort gate:** reviewed source lane plus focused sync and fresh runtime resolution of generic and XSS overlays.
- **Promotion gate:** no stable promotion without explicit owner direction.

## Decision record

- 2026-10-14 — Created feature worktree and class route; static tests and offline scenario passed. Independent review identified only the protected `AGENTS.md` maintenance gap; integration held pending authorization.
- 2026-10-14 — Ryushe selected BBH `AGENTS.md` as the contributor entry. Protected edit succeeded; route regression passes. The earlier proposed AI Policies `AGENTS.md` edit was not made.
- 2026-10-14 — Independent reviewer found only a stale dossier handoff state; corrected the committed AGENTS.md/test provenance before integration.
