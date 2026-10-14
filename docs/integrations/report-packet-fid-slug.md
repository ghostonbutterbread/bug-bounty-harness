# Finding packet layout integration dossier

- **Status:** accepted BBH feature (independent no-edit review of `e2b71e4`; beta integration pending)
- **Owner:** Hermes / t_f9946642
- **Branch:** `feat/report-packet-fid-slug-tf9946642`
- **Base commit:** `0e6fbc95d7f22c51f04eced826d31f21f7ac259b`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-13
- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** `d17d5836c49d0ed02a168a7c837e14b932b7b3bf`
- **Feature implementation commit(s):** `16fdd0e2932a7fde127a1234742e088f0d34979f`, `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`, `252a2e6131cf84a134d98ce0304c4b660b6f9bbb`, `420ef2dd2aafa485d15bebefec0b4d5ee547e614`, `79a42794c7fa8f00e1b4f1345944105435a107d9`, `e4935853879fcb25643073ab4b251a08a902153f`, `d17d5836c49d0ed02a168a7c837e14b932b7b3bf`
- **Inspiration / canonical references:** `/home/ryushe/.hermes/plans/2026-10-13_152453-report-packet-layout.md`; Bounty Core provider branch `feat/report-packet-fid-slug-tf9946642`.

## Intent

Consume Bounty Core's stable FID-and-vulnerability-slug packet path, retain exact FID final-report registration, and route BBH skills to the resolved evidence packet. Prove all behaviors without contacting a target or mutating production Shared data.

## Implemented contract

BBH consumes the provider's persisted `finding['report_dir']` for new descriptive evidence packets and retains exact-FID legacy packet reads. Registration remains a pre-existing FID-named report handoff; operator submission changes generate/remove navigation without moving evidence. Sync skips canonical D-number packet artifacts, but still imports raw reports. Dynamic validation's packet lookup and lifecycle scan follow the ledger pointer. Standalone Bunny and profile-local finding-ingestion skills contain the requested one-line-paragraph instruction and ledger-resolved packet guidance; BBH's security-reporting, root card, and bounty-notes examples align.

Provider beta is published at **`fd66f7ab9069a92c2aae624c85c00d15b6b34c90`** (contains accepted implementation `180ebd0877128979199b3883d4d800f084c68071`, remote ref fetched/read back). BBH pins this immutable SHA and its checkout-local `.venv` imports the installed wheel, not sibling source. **This is feature-worktree verification; BBH beta and active runtime remain separate gates.**

## Evidence and review

- Baseline: `python3 -m pytest agents/test_finding_report.py agents/test_manual_hunter.py -q` — 38 passed, 13 subtests passed on fetched origin/beta.
- Consumer RED: descriptive path + submission E2E tests in `agents/test_finding_report.py` and `agents/test_manual_hunter.py` failed on old FID-only provider; provider source-contract smoke now passes their focused suites.
- Consumer local contract smoke: `PYTHONPATH=<provider-feature-worktree>:<BBH-feature-worktree> python3 -m pytest agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_dynamic_validation.py agents/test_report_checker.py agents/test_base_team_review.py -q --tb=short` — **131 passed, 13 subtests passed** with corrected provider. The new actual CLI-process E2E (`test_cli_packet_lifecycle_keeps_stable_path_and_submission_view`) was RED against old installed/source Core (`D01` vs descriptive packet) and GREEN against the provider feature. This still is not installed-pinned proof.
- Provider complete `python3 -m pytest -q --tb=short` — **184 passed** on integration beta. Independent no-edit review ACCEPTED implementation `180ebd0` (184 full / 54 focused); provider beta merge `fd66f7a` pushed, fetched, and read back.
- BBH feature checkout `./setup.sh --install-python-deps` installed from `requirements.txt` into `.venv`; `bounty_core.__file__` points inside this checkout's `.venv/lib/python3.11/site-packages/`, and distribution `direct_url.json` resolves requested and commit IDs to full `fd66f7ab9069a92c2aae624c85c00d15b6b34c90`. `uv pip freeze --python .venv/bin/python` agrees.
- `.venv/bin/python -m pytest agents/test_app_mapper.py agents/test_base_team_ledger_writes.py agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_dynamic_validation.py agents/test_report_checker.py agents/test_base_team_review.py tests/test_runtime_dependencies.py -q --tb=short` — **242 passed, 13 subtests passed** with installed pinned Core. Selected real CLI subprocess create/register/submit/reverse plus path negatives and historic fallback: **45 passed**. No source `PYTHONPATH` override.
- Broad `agents/` suite collected 2,360 tests. First `-x -vv` captured a stale FID-only expectation in AppMap E2E (185 passed, 1 failed); next `-x -q` captured a stale base-team packet-parent assertion (235 passed, 1 failed). Both were updated to assert the generated descriptive packet/ledger pointer. A subsequent foreground run reached ~20% before its 180-second tool limit; other background attempts returned host environment errors (`GOROOT` refers to absent `/usr/local/go`; Linuxbrew Python 3.14 lacks pytest) before a usable pytest summary. **Full agents/ suite is not green.**
- Independent no-edit BBH acceptance: **ACCEPT for beta** on `e2b71e4`; reviewer reran installed pinned **242 tests, 13 subtests**, selected actual CLI packet tests **11/11**, checked historical fallback, symlink rejection, raw sync retention and reversible category/severity/submitted views. The full `agents/` suite remains without a green receipt but was **not a beta blocker** on reviewed focused evidence; runtime and stable promotion are not accepted.
- Merge/ancestry evidence: feature based on fetched `origin/beta` 0e6fbc95d7f22c51f04eced826d31f21f7ac259b.

## Blockers and deferred work

- **Missing test or evidence:** Beta integration installed recheck and remote readback; full `agents/` suite remains unverified and is a future broad-suite gate, not this reviewed beta gate. Runtime skill synchronization is separate.
- **Command / fixture / environment needed:** `.venv/bin/python -m pytest agents/test_app_mapper.py agents/test_base_team_ledger_writes.py agents/test_finding_report.py agents/test_manual_hunter.py agents/test_sync_reports.py agents/test_dynamic_validation.py agents/test_report_checker.py agents/test_base_team_review.py tests/test_runtime_dependencies.py -q --tb=short`; installed `direct_url.json` full SHA; final CLI subprocess cycle.
- **Trigger to run it:** merge accepted feature into fetched current beta, re-sync integration checkout environment and re-run installed tests before push.
- **Why it blocks integration, activation, or promotion:** Beta merge and installed recheck remain; runtime skill version is not inferred from source publication.
- **Next completion step / successor reference:** integrate BBH beta from clean integration checkout, push/readback; then verify selected runtime and synchronize Bunny skill separately.

## Interruption / resume handoff

- **Owning feature branch/ref:** `feat/report-packet-fid-slug-tf9946642`
- **Latest immutable recovery checkpoint:** `d17d5836c49d0ed02a168a7c837e14b932b7b3bf`
- **Feature implementation commit(s):** `16fdd0e2932a7fde127a1234742e088f0d34979f`, `cdd85a34797f4cb1e98fbfc96472e57fff2b65b9`, `252a2e6131cf84a134d98ce0304c4b660b6f9bbb`, `420ef2dd2aafa485d15bebefec0b4d5ee547e614`, `79a42794c7fa8f00e1b4f1345944105435a107d9`, `e4935853879fcb25643073ab4b251a08a902153f`, `d17d5836c49d0ed02a168a7c837e14b932b7b3bf`
- **Exact resume point:** integrate independently accepted BBH feature into clean current beta checkout, retire dossier from beta, re-sync/install and test, push/readback. Runtime/Bunny sync separate.
- **Working-tree state at handoff:** task-owned BBH reconciliations committed as checkpoint; verify status before further edits.

## Decision gates

- **Integration gate:** provider published/pinned, consumer tests and independent review pass, current beta reconciled.
- **Activation / cohort gate:** verify installed dependency and synchronized Bunny/BBH skill content in selected runtime.
- **Promotion gate:** none requested; stable is separate.

## Decision record

- 2026-10-13 — created BBH feature worktree and recorded baseline; provider implementation delegated in separate repository.
- 2026-10-13 — independent no-edit BBH review accepted `e2b71e4` for beta after installed pinned 242+13 tests; full agents suite and runtime activation remain separate gates.
