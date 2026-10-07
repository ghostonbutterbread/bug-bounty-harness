# Prior-work stop-sign refinement integration dossier

- **Status:** feature
- **Owner:** Hermes
- **Branch / owning ref:** `fix/prior-work-stop-sign`
- **Base commit:** `7fb2e51c88c95270d3de40bc357fd89cac880488`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-07
- **Latest immutable recovery checkpoint:** `fc4007177311c0f4a6ec898e97f866f81a523a9c`
- **Feature implementation commit(s):** `fc4007177311c0f4a6ec898e97f866f81a523a9c`
- **Inspiration / canonical references:** Ryu clarified in the same Discord thread that normal hunts must not spend time deepening confirmed/submitted findings; task `t_7818be03`.

## Intent

Keep closed findings out of normal hunt selection, but permit a compact exact file/class dedupe stop sign. Avoid encouraging agents to use a known finding as an adjacent-chain or inspiration target. The user is reconsidering whether to hide closed findings entirely; publication stays on hold pending that visibility decision.

## Implemented contract

`me_ledger.py prior-work` now returns only `known_prior_work`, `confirmed`, `submitted`, and `duplicate` booleans alongside the requested key, with no FID, title, report, or proof. Ledger and Hunter Loop guidance say a positive reply ends that file/class line for an ordinary new-finding hunt. Independently observed unrelated surfaces/classes remain eligible. Full FID, report, or extension access is an explicit retest/report task. Focused Recon no longer suggests past confirmed work as rebound ideas.

## Evidence and review

- `python -m pytest -q agents/test_finding_visibility.py agents/test_me_ledger.py agents/test_ledger_v2.py agents/test_manual_hunter.py tests/test_ledger_skill_visibility.py`: 65 passed, 21 subtests; `git diff --check` clean.
- Neighbor alignment: `agents/index.md` cold surface; `/ledger` owns retrieval; `/hunter-loop` and `/focused-recon` route normal hunts; `/manual-hunter` owns operator submission status. No change to exact FID command for explicitly scoped work.
- Independent review: pending.

## Blockers and deferred work

- User is reconsidering default closed-finding visibility. Do not push beta or claim Hoster activation until the owner confirms this recommendation: default work queue hidden; targeted yes/no dedupe; full closed records only on explicit request.
- Exact file/class matching is not semantic equivalence. A positive is a stop sign for that line; a miss is not proof of novelty.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/prior-work-stop-sign`
- **Latest immutable recovery checkpoint:** `fc4007177311c0f4a6ec898e97f866f81a523a9c`
- **Feature implementation commit(s):** `fc4007177311c0f4a6ec898e97f866f81a523a9c`
- **Exact resume point:** reconcile independent review, then hold remote beta publication pending Ryu's visibility/default decision.
- **Working-tree state at handoff:** clean after the dossier checkpoint commit.

## Decision gates

- **Integration gate:** independent review, focused checks, clean current beta.
- **Activation / cohort gate:** owner-approved visibility/default semantics before remote beta push or Hoster rollout.
- **Promotion gate:** no main promotion requested.

## Decision record

- 2026-10-07 — scope corrected from 'inspiration/adjacent ideas' to stop-sign dedupe; beta remote publication held.
