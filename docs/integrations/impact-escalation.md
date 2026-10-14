# Impact escalation integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/impact-escalation`
- **Base commit:** `ce0804a9853597e2e955df5f3914d98342a49fd0`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-14
- **Owning feature branch/ref:** `feat/impact-escalation`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Inspiration / canonical references:** Ryushe's Discord impact-escalation design; AI Policies `impact-fit-policy`, `assumption-testing`, and generic `impact-escalation` beta source.

## Intent

After prompt initial finding capture, explore defensible application-specific impact before a final Bunny report. Add XSS idea overlay and route it without turning the report writer into a live hunter. Keep existing live-testing, account, evidence, and reporting owners authoritative.

## Implemented contract

`agents/index.md`, `manual-hunter`, `security-reporting`, and `xss` route a captured FID to generic `impact-escalation`, then `xss-escalation` when confirmed XSS. The overlay prompts account control, durable auth, actions, data, and delivery; claimed UI/API guards route to `assumption-testing`. New effect proof remains in the same FID and `EVIDENCE.md`; final report remains Bunny's report-only job. No new target-testing authorization or ledger schema.

## Evidence and review

- Tests and commands: `python3 -m pytest -q tests/test_impact_escalation_routes.py tests/test_security_reporting_skill.py tests/test_reporting_markdown.py` (7 passed, 30 subtests); `git diff --check` passed. AI Policies lint and 43 tests passed separately.
- Independent review: fresh agent found no behavioral defect; medium maintenance gap remains: protected `AGENTS.md` pointer absent after approval timeout. Not PASS for integration.
- Replay/cohort/fixture evidence: offline agent evaluation of fictional stored XSS FID D17. It challenged a UI old-password claim against two routes: one enforced the guard, the other had a simulated owned-fixture email-state change. It did **not** claim ATO because login/recovery binding and fresh-session usability were unproven. Stale-auth token and viewer invite branches stayed negative. No real target traffic or effect.
- Merge/ancestry evidence: feature based on fetched `origin/beta` `ce0804a`.

## Blockers and deferred work

- **Missing test or evidence:** Requested repository `AGENTS.md` maintenance instruction is not added. The protected-file approval timed out; no consent was obtained, and this turn must not retry the edit through any path.
- **Command / fixture / environment needed:** A fresh explicitly approved edit to the repository agent-instruction file in a later authorized context.
- **Trigger to run it:** Ryushe approves the protected-file write through the approval flow.
- **Why it blocks integration, activation, or promotion:** User expressly requested maintainers be told to update the generic skill's bottom class route list when adding subskills. The skill itself contains the route-maintenance rule, but the repository contributor guide does not yet carry the pointer.
- **Next completion step / successor reference:** Obtain approval, add concise AGENTS.md pointer, rerun checks and independent review before beta merge. Do not circumvent the timed-out approval.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/impact-escalation`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** reconcile reviewer/scenario output, update dossier, commit recoverable feature branch; request fresh approval on a later turn for AGENTS.md, then finish review/integration.
- **Working-tree state at handoff:** intentionally uncommitted while tests/review run.

## Decision gates

- **Integration gate:** passing tests, independent review resolved, repository AGENTS.md maintenance instruction approved and written; reconcile current beta before merge.
- **Activation / cohort gate:** reviewed source lane plus focused sync and fresh runtime resolution of generic and XSS overlays.
- **Promotion gate:** no stable promotion without explicit owner direction.

## Decision record

- 2026-10-14 — Created feature worktree and class route; static tests and offline scenario passed. Independent review identified only the protected `AGENTS.md` maintenance gap; integration held pending authorization.
