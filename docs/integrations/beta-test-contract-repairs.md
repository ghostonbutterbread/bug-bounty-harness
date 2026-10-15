# Beta test contract repairs — integration dossier

- **Status:** review-ready; release/reconciliation pending.
- **Owner:** Hermes / Ryushe.
- **Branch / worktree:** `fix/bbh-baseline-tests-tf64b1792` at `/home/ryushe/worktrees/bbh-beta-baseline-tests`.
- **Base commit:** `5bd12fbb76f8506dfc4e78eab6de59d904a2a9c5`.
- **Intended target:** `beta` (fetched remote advanced; reconcile before integration).
- **Last updated:** 2026-10-15.
- **Recovery checkpoint:** none yet; commit this dossier with the repair.
- **Inspiration:** clean-beta failures in Hoster authority and FID packet tests; a broader-suite zero-day assertion identified during review.

## Intent and implemented contract

Correct three stale test expectations without changing production behavior: Hoster's explicitly authorized, credential-checked scripts-only maintenance boundary; FID evidence-only packets must be explicitly requested and their immutable `report_dir` read from the finding; zero-day reviewed promotion refreshes canonical evidence but does not generate a final report. No changes to Hoster policy or default packet-writing semantics.

## Evidence and review

- Original Hoster and FID assertions reproduced on clean beta `5bd12fb`: 2 failed, 14 passed.
- Zero-day chainer assertion reproduced red on this branch before its one-line correction.
- Checkout-local pinned interpreter with `PYTHONPATH` set to this branch: `agents/test_zero_day_team.py agents/test_ledger_v2.py tests/test_hoster_script_authority.py -q`: **73 passed, 2 subtests passed**; `git diff --check` clean.
- Independent review approved the first two test repairs: 113 passed, 26 subtests. The zero-day correction needs independent review.
- Remote beta advanced after this branch's base. Reconcile and rerun before merging.

## Blockers, handoff and decisions

- Integration gate: independent review of the complete three-test diff, reconcile current `origin/beta`, rerun relevant suites, then commit/review/integrate in clean beta worktree.
- Activation: no separate executable/skill change; ship alongside reviewed live Coverage rollout.
- Promotion: beta only; no stable promotion requested.
- Deferred: no production code change, no Shared Brain migration.
- **Exact resume point:** commit scoped repair and dossier, reconcile fetched beta, independently re-review final diff, then merge; remove this temporary dossier from beta after accepted merge.
