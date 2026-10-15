# Beta test contract repairs — integration dossier

- **Status:** independently approved; reconciled to current beta and ready for scoped integration.
- **Owner:** Hermes / Ryushe.
- **Branch / worktree:** `fix/bbh-baseline-tests-tf64b1792` at `/home/ryushe/worktrees/bbh-beta-baseline-tests`.
- **Base commit:** `5bd12fbb76f8506dfc4e78eab6de59d904a2a9c5`.
- **Intended target:** `beta`, reconciled to `origin/beta` at `116a4ec25690a1f1a11a768b8e51d1c651cb9ff4` via merge `c8cacb74eff831eb31f711a5e24f8588cae8fbed`.
- **Last updated:** 2026-10-15.
- **Recovery checkpoint:** implementation `15a0860f18fab4b6924d8467edaa850a4223ab1f`, reconciliation `c8cacb74eff831eb31f711a5e24f8588cae8fbed`.
- **Inspiration:** clean-beta failures in Hoster authority and FID packet tests; a broader-suite zero-day assertion identified during review.

## Intent and implemented contract

Correct three stale test expectations without changing production behavior: Hoster's explicitly authorized, credential-checked scripts-only maintenance boundary; FID evidence-only packets must be explicitly requested and their immutable `report_dir` read from the finding; zero-day reviewed promotion refreshes canonical evidence but does not generate a final report. No changes to Hoster policy or default packet-writing semantics.

## Evidence and review

- Original Hoster and FID assertions reproduced on clean beta `5bd12fb`: 2 failed, 14 passed.
- Zero-day chainer assertion reproduced red on this branch before its one-line correction.
- Checkout-local pinned interpreter with `PYTHONPATH` set to this branch: `agents/test_zero_day_team.py agents/test_ledger_v2.py tests/test_hoster_script_authority.py -q`: **73 passed, 2 subtests passed**; `git diff --check` clean.
- Independent review approved the full three-test repair at prior beta, 87 passed/2 subtests; post-reconciliation rerun: **73 passed, 2 subtests passed**, diff check clean. No production code changed.
- Current beta contains additional Chromium, JS-router and manual-hunter updates, preserved by the reconciliation merge. Final merge must fetch and verify current beta tip.

## Blockers, handoff and decisions

- Integration gate: approved; fetch current beta before merge, confirm no overlapping changes, run integrated checks, and remove temporary dossier from beta.
- Activation: no separate executable/skill change; ship alongside reviewed live Coverage rollout.
- Promotion: beta only; no stable promotion requested.
- Deferred: no production code change, no Shared Brain migration.
- **Exact resume point:** commit final approval dossier, merge feature into clean beta release checkout, remove dossier, test and push named beta. No Hoster change yet.
