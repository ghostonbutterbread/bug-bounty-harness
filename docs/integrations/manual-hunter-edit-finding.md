# Manual hunter finding-edit integration dossier

- **Status:** feature (review pending)
- **Owner:** Hermes
- **Branch / owning ref:** `feat/manual-hunter-edit-finding`
- **Base commit:** `3a25123903152994b9b431ac668c47ac3ad14e79`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Inspiration / canonical references:** Ryu's correction to the duplicate-comment request; existing `bounty_core.ledger.patch_finding_by_fid` and `agents/ledger.py`.

## Intent

Give agents an explicit way to replace false ledger content and add verified facts to an existing finding by FID. A duplicate comment is not a content edit. Preserve identity, observation metadata, submission outcome, and hand-edited reports.

## Implemented contract

`manual_hunter.py <program> --lane <lane> --edit-finding <FID> --patch-file <JSON>` accepts an explicit, nonempty content-field patch. It rejects unknown/protected fields, invalid value types, and nonexistent FIDs. Bounty Core patches the exact FID and refreshes generated report/index projections. Hand-edited reports remain preserved and require narrative reconciliation. No claim of a platform submission update.

## Evidence and review

- Tests and commands: pinned checkout venv `python -m pytest -q agents/test_manual_hunter.py agents/test_ledger_v2.py tests/test_skill_command_lane_safety.py::SkillCommandLaneSafetyTests::test_canonical_skills_do_not_teach_stale_checkout_or_import_routing` — 39 passed, 9 subtests; CLI `--help` includes both new flags; `git diff --check` passed.
- Independent review: pending.
- Replay/cohort/fixture evidence: temporary fixture ledger exercises content correction, wrong FID, protected fields, lane isolation, generated report refresh, preserved hand-edited report.
- Merge/ancestry evidence: branch from fetched `origin/beta` at base above.

## Blockers and deferred work

- Independent review and beta integration are pending; rerun focused tests after integration. No live program finding was mutated in verification.
- Full lane-safety suite has a pre-existing unrelated historical-dossier command example failure; focused canonical-skill safety assertion passes.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/manual-hunter-edit-finding`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commits:** none yet
- **Exact resume point:** review diff and committed tests, independent review, beta merge.
- **Working-tree state at handoff:** implementation uncommitted until checkpoint below.

## Decision gates

- **Integration gate:** independent approval, clean current beta, focused tests.
- **Activation gate:** verify beta runtime skill projection and actual CLI source after merge.
- **Promotion gate:** stable requires separate owner direction.

## Decision record

- 2026-09-25 — built explicit FID edit path on feature branch after user clarified intended behavior; review pending.
