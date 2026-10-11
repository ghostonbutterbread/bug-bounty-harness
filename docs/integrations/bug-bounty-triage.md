# Upstream triage adaptation integration dossier

- **Status:** review-ready
- **Owner:** Hermes; Kanban `t_16b9d4f5`
- **Branch / owning ref:** `feat/triage-report-adaptation`
- **Worktree:** `/home/ryushe/worktrees/bbh-triage-report-adaptation`
- **Base commit:** `46f2b9a105e8e0d8eeb01537b3361560f1b3b27a`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-11
- **Latest immutable recovery checkpoint:** `f47d2dccb0c65a3ba6b94ac1e434ef3d8a406f0f`
- **Feature implementation commits:** `f47d2dccb0c65a3ba6b94ac1e434ef3d8a406f0f`
- **Source:** Sequester-AG/bug-bounty-triage at `9684e1bfc876e841f9c789f0b258902b43d461e4`, MIT; copy of license retained.

## Intent

Bring upstream's evidence-led validation, readiness, escalation, and concise triager reporting into BBH without creating a competing canonical report or violating owned-scope, browser, email, or secret boundaries. This is an internal skill derivative, not a public GitHub fork or upstream PR.

## Implemented contract

`bug-bounty-triage` owns evidence-gap and GREEN/YELLOW/RED triage. It routes live validation to the authorized owner and applicable policies, security browser to the Chromium provisioner/task MITM, mail to approved identity + `mail`/Composio, and final report to existing per-FID `security-reporting` and `finding_submission.py`. No live target test or report submission is part of this implementation. Registry route and focused contract tests included.

## Evidence and review

- Tests: `python3 -m pytest -q tests/test_bug_bounty_triage_skill.py tests/test_security_reporting_skill.py tests/test_reporting_markdown.py` (11 passed, 50 subtests); `python3 -m pytest -q tests --ignore=tests/test_hoster_script_authority.py` (216 passed, 1 skipped, 173 subtests); `git diff --check` passed. The unfiltered suite has one pre-existing `test_hoster_script_authority.py` failure (missing legacy `AGENTS.md` phrase), reproduced on unchanged beta.
- Independent review: initial REVISE (missing FID handoff and ambiguous report ownership); fresh read-only re-review of implementation `f47d2dc` and dossier-only tip `9c13de8` returned PASS with no new blocker.
- Fixture/live evidence: static-only; no target requested and no live validation performed.
- Merge/ancestry evidence: pending current-beta preflight.

## Blockers and deferred work

- Local activation needs a reviewed beta merge and profile-scoped skill projection; upstream was intentionally not forked publicly. No live report exemplar is available without a named finding and owned scope.
- No missing correctness evidence is currently known. Unfiltered suite remains red solely for the identical pre-existing Hoster authority test failure; targeted and remaining tests pass. No live finding exemplar exists without a named program/FID.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/triage-report-adaptation`
- **Latest immutable recovery checkpoint:** `f47d2dccb0c65a3ba6b94ac1e434ef3d8a406f0f`
- **Feature implementation commits:** `f47d2dccb0c65a3ba6b94ac1e434ef3d8a406f0f`
- **Exact resume point:** preflight against current beta, integrate reviewed files while excluding this dossier, then verify source push and runtime activation.
- **Working-tree state at handoff:** clean after this dossier-only checkpoint commit.

## Decision gates

- **Integration:** focused/full tests and independent review, clean current beta, removal of this branch-local dossier from beta merge.
- **Activation:** reviewed beta source present in configured sync profile and loadable by a fresh agent.
- **Promotion:** stable main only on explicit direction.

## Decision record

- 2026-10-11 - opened internal adaptation from the MIT upstream at the recorded commit.
- 2026-10-11 - review PASS after the FID and submission-authorship corrections; beta integration approved subject to clean preflight.
