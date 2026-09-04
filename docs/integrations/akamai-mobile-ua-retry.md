# Akamai mobile User-Agent retry integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch:** `feat/akamai-mobile-ua-retry`
- **Base commit:** `496fa9f8e7c34aa607881151ec4d824034dd5cd3`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-03
- **Owning feature branch/ref:** `feat/akamai-mobile-ua-retry`
- **Latest immutable recovery checkpoint:** `99eb70a1f9acda092fe76ddea5aae08ba4293075`
- **Feature implementation commit(s):** `99eb70a1f9acda092fe76ddea5aae08ba4293075`
- **Inspiration / canonical references:** Hoster runtime observation of an Akamai block differential; Discord thread `1545266116836991056`; WAF Live Policy.

## Intent

Add one browser-realistic Android Chrome User-Agent retry to the existing Akamai Tier 1 sequence. The retry must run only after an Akamai block is fingerprinted, preserve the existing delay and request mechanics, and retain the existing bypass evidence logging. It must not embed a target-specific app identity, enable live probing, alter rate controls, or claim a universal bypass.

## Implemented contract

Pending implementation. The Akamai list will retain the desktop Chrome retry and add a distinct Android Chrome retry immediately after it. Sync and async Tier 1 paths consume the shared list, so both will make the same evidence-gated retry. Fixture tests will prove the mobile User-Agent is attempted after an Akamai-shaped block and that a clean response is returned.

## Evidence and review

- Tests and commands: `PYTHONPATH=/home/ryushe/worktrees/bbh-akamai-mobile-ua-retry /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m unittest tests/test_waf_interceptor.py` (4 passed); `PYTHONPATH=/home/ryushe/worktrees/bbh-akamai-mobile-ua-retry /home/ryushe/projects/bug_bounty_harness/.venv/bin/python -m unittest discover -s tests -p 'test_*.py'` (76 passed)
- Independent review: identified a high-severity `wrap_async()` retry-path defect; the branch now passes the original path and query into `_async_bypass()` and has a regression test. Re-review pending.
- Replay/cohort/fixture evidence: deterministic local fake-response tests; no live target traffic
- Merge/ancestry evidence: feature starts from local beta `496fa9f8e7c34aa607881151ec4d824034dd5cd3`, which was confirmed clean and four commits ahead of `origin/beta`

## Blockers and deferred work

- **Missing test or evidence:** no target-independent method can establish a universal Akamai bypass.
- **Command / fixture / environment needed:** target-owned, scoped, rate-limited validation only if a future run has a named surface and authorization.
- **Trigger to run it:** a permitted Akamai block where the next User-Agent differential answers a concrete application testing question.
- **Why it blocks integration, activation, or promotion:** it does not block code integration; it blocks any efficacy claim or automatic runtime activation.
- **Next completion step / successor reference:** implement fixture tests, obtain independent review, and reconcile the locally-ahead beta integration lane before a merge decision.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/akamai-mobile-ua-retry`
- **Latest immutable recovery checkpoint:** `99eb70a1f9acda092fe76ddea5aae08ba4293075` (the current branch will also contain the following dossier-only checkpoint)
- **Feature implementation commit(s):** `99eb70a1f9acda092fe76ddea5aae08ba4293075`
- **Exact resume point:** obtain re-review of the retry-path correction, then reconcile the locally-ahead beta lane before requesting integration.
- **Working-tree state at handoff:** clean after the corrective checkpoint is committed.

## Decision gates

- **Integration gate:** focused tests pass; independent review has no unresolved issue; local `beta` divergence from `origin/beta` is explicitly reconciled.
- **Activation / cohort gate:** an explicit runtime deployment decision and a non-mutating lane-isolation smoke check.
- **Promotion gate:** user-directed beta-to-main promotion only.

## Decision record

- 2026-09-03 — created feature branch from current clean local beta after fetching `origin/beta`; Hoster inspection confirmed runtime beta has an Akamai desktop-UA retry but no Android Chrome retry.
- 2026-09-03 — independent review found `wrap_async()` retried the root rather than the blocked path; corrected path/query propagation and added a regression test before re-review.
