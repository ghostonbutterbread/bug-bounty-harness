# Manual hunter finding-edit integration dossier

- **Status:** approved for beta integration after reconciliation
- **Owner:** Hermes
- **Branch / owning ref:** `feat/manual-hunter-edit-finding`
- **Base commit:** `3a25123903152994b9b431ac668c47ac3ad14e79`
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-25
- **Latest immutable recovery checkpoint:** `661aacebd646e6b30411adf7b69462d4c60ff2c1`
- **Feature implementation commits:** `661aacebd646e6b30411adf7b69462d4c60ff2c1`
- **Inspiration / canonical references:** Ryu's correction to the duplicate-comment request; existing `bounty_core.ledger.patch_finding_by_fid` and `agents/ledger.py`.

## Intent

Give agents an explicit way to replace false ledger content and add verified facts to an existing finding by FID. A duplicate comment is not a content edit. Preserve identity, observation metadata, submission outcome, and hand-edited reports.

## Implemented contract

`manual_hunter.py <program> --lane <lane> --edit-finding <FID> --patch-file <JSON>` accepts an explicit, nonempty content-field patch. It rejects unknown/protected fields, invalid value types, and nonexistent FIDs. Bounty Core patches the exact FID and refreshes generated report/index projections. Hand-edited reports remain preserved and require narrative reconciliation. No claim of a platform submission update.

## Evidence and review

- Tests and commands: checkout-local `.venv/bin/python -m pytest -q agents/test_manual_hunter.py agents/test_ledger_v2.py tests/test_runtime_dependencies.py tests/test_skill_command_lane_safety.py::SkillCommandLaneSafetyTests::test_canonical_skills_do_not_teach_stale_checkout_or_import_routing` — 42 passed, 9 subtests. Real CLI fixture with `--root` added then edited D01: old generated type index removed, new index present, title/vulnerability_name and severity/severity_label aligned. `git diff --check` passed.
- Independent review: initial review blocked stale generated type indexes and stale title/severity aliases. Bounty Core provider fix passed independent review, merged/pushed as `8cc64e68bc93919573c5e3cb2662283889d7858c`; consumer pin and `direct_url.json` match. Final consumer review approved; beta had advanced to `082c027`, merged into feature at `349dd8c`, and focused tests reran: 42 passed, 9 subtests.
- Replay/cohort/fixture evidence: temporary fixture ledger exercises content correction, wrong FID, protected fields, lane isolation, generated report refresh, preserved hand-edited report.
- Merge/ancestry evidence: branch from fetched `origin/beta` at base above.

## Blockers and deferred work

- Beta merge, installed beta dependency refresh, and activation check remain. No live program finding was mutated in verification.
- Full lane-safety suite has a pre-existing unrelated historical-dossier command example failure; focused canonical-skill safety assertion passes.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/manual-hunter-edit-finding`
- **Latest immutable recovery checkpoint:** `661aacebd646e6b30411adf7b69462d4c60ff2c1`
- **Feature implementation commits:** `661aacebd646e6b30411adf7b69462d4c60ff2c1`
- **Exact resume point:** review diff and committed tests, independent review, beta merge.
- **Working-tree state at handoff:** clean after dossier checkpoint.

## Decision gates

- **Integration gate:** independent approval, clean current beta, focused tests.
- **Activation gate:** verify beta runtime skill projection and actual CLI source after merge.
- **Promotion gate:** stable requires separate owner direction.

## Decision record

- 2026-09-25 — built explicit FID edit path on feature branch after user clarified intended behavior; review pending.
