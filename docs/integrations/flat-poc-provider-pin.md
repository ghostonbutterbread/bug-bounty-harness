# Flat PoC packet provider pin integration dossier

- **Status:** review-ready
- **Owner:** Hermes
- **Branch:** `feat/flat-poc-provider-pin-t21d4b6ff`
- **Base commit:** `23e7dcd11c9b1abba826137c22946ecf6a794d9b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-14
- **Owning feature branch/ref:** `feat/flat-poc-provider-pin-t21d4b6ff`
- **Latest immutable recovery checkpoint:** pending initial implementation commit
- **Feature implementation commit(s):** pending initial implementation commit
- **Inspiration / canonical references:** Ryu's packet root PoC request in Discord thread 1559687914517045351; published Bounty Core beta `035c9a165fb6addfebb814d66b1b7f6143ab7e69` containing independently reviewed provider implementation `1ee09696c0cb275fa7ab7a6d24516f98faa3f2fb`.

## Intent

Update the immutable provider pin so BBH's real CLI consumes the new flat packet scaffold. Preserve final report registration, packet paths, and submission views; don't activate a live runtime.

## Implemented contract

`requirements.txt` pins `035c9a165fb6addfebb814d66b1b7f6143ab7e69`. Pin tests require that SHA and reject `fd66f7ab9069a92c2aae624c85c00d15b6b34c90`. The disposable CLI create/register/submit/drop test additionally asserts there is no precreated `poc/` or `evidence/`, writes `poc.py` alongside `EVIDENCE.md` and the final report, and verifies it survives later state changes.

## Evidence and review

- Tests and commands: pin tests and CLI packet test failed RED against old manifest/installed provider. `./setup.sh --install-python-deps` installed checkout-local `.venv`, `direct_url.json` commit was exact new beta SHA, and installed `.venv/bin/python -m pytest agents/test_app_mapper.py agents/test_base_team_ledger_writes.py agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_dynamic_validation.py agents/test_report_checker.py agents/test_base_team_review.py tests/test_runtime_dependencies.py -q --tb=short` passed **242 tests, 13 subtests**. Selected pin/CLI suite **9 passed**.
- Independent review: pending.
- Replay/cohort/fixture evidence: CLI subprocesses under disposable roots; no production Shared writes or live-target action.
- Merge/ancestry evidence: based on fetched BBH `origin/beta` `23e7dcd11c9b1abba826137c22946ecf6a794d9b`.

## Blockers and deferred work

- **Missing test or evidence:** independent no-edit consumer review; beta integration rerun and readback.
- **Command / fixture / environment needed:** checkout-local installed focused suite above in clean beta integration checkout.
- **Trigger to run it:** committed candidate accepted; beta fetched current.
- **Why it blocks integration, activation, or promotion:** normal consumer release gate; runtime activation is separate.
- **Next completion step / successor reference:** review, integrate beta with dossier retired, reinstall test and read back remote ref. No historical packet deletion or movement.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/flat-poc-provider-pin-t21d4b6ff`
- **Latest immutable recovery checkpoint:** pending initial implementation commit
- **Feature implementation commit(s):** pending initial implementation commit
- **Exact resume point:** commit candidate, record SHA here, obtain independent no-edit review.
- **Working-tree state at handoff:** intentionally uncommitted pending candidate commit.

## Decision gates

- **Integration gate:** independently accepted consumer + installed beta checks.
- **Activation / cohort gate:** explicit active BBH runtime checkout and skill projection update, not this beta release.
- **Promotion gate:** separate stable decision.

## Decision record

- 2026-10-14 — installed-pinned candidate passed 242+13 focused checks, awaiting review.
