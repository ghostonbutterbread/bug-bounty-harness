# Atomic report import integration dossier

- **Status:** blocked pending Core release, consumer pin, installed verification and independent review
- **Owner:** delegated BBH sync importer worker; parent owns integration
- **Branch:** `fix/atomic-report-import`
- **Worktree:** `/home/ryushe/worktrees/bbh-atomic-report-import`
- **Base commit:** `4ba241ce9859e7ee4964566e54976aeb032336fd` (fresh `origin/beta`)
- **Intended integration target:** `beta` (eventual authorized promotion to `master` is separate)
- **Last updated:** 2026-11-17
- **Owning feature branch/ref:** `fix/atomic-report-import`
- **Latest immutable recovery checkpoint / feature implementation:** `6329b0f4ea48281726acfe42ec064cbfd5bbd85b`; branch tip contains this later dossier-only handoff.
- **Inspiration / canonical reference:** Core candidate `/home/ryushe/worktrees/core-raw-collision-minimal` at `266d0da8d7cc21bfbd5165667b2bf0aa734bb121`, unreviewed/unpublished; `VersionedFindingsLedger.import_finding(..., packet_mode='evidence_only')`.

## Intent and implemented contract

`sync_reports` formerly called `check()` (which reserves) and then separately materialized the finding. On a pre-existing raw/packet collision, the second operation failed after the reservation, causing the next run to call the incomplete record a duplicate. Use Core's locked check/reserve/materialize operation. Completed duplicates remain skipped; FID conflicts retain the previous nonzero, continue-and-summarize behavior. Only Core's exact `finding FID already assigned: ` ValueError prefix is classified as an FID conflict; other ValueErrors and I/O errors propagate as failures. This prefix is the candidate's current contract, not a typed exception. No dependency pin changed.

The Core operation marks interrupted materializations as pending and retries them; it cannot identify or automatically repair pre-existing partial reservations created by the old split path. Do not claim all old rows are repaired. Core states packet/index I/O is not fully transactional and the lock coordinates only cooperating writers.

## Evidence and review

- Red/green: `agents.test_sync_reports_atomic.AtomicReportImportCLI.test_raw_collision_fails_without_reservation_then_retry_imports` failed on the original BBH source because ledger bytes changed after a raw collision; passed after the consumer fix.
- Final focused run: 167 tests passed using `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD:/home/ryushe/worktrees/core-raw-collision-minimal" ... python -m unittest agents.test_sync_reports agents.test_sync_reports_atomic agents.test_report_source_cli agents.test_manual_hunter agents.test_report_checker agents.test_report_checker_exceptional agents.test_finding_report -q`. Log: `/home/ryushe/.hermes/cache/scratch/bbh-atomic-focused-final.log`; scratch is ephemeral. Six expected manual-hunter class-inference warnings appeared.
- Real CLI synthetic fixtures cover raw and FID collisions, byte-preserving non-reservation, ordinary canonical raw/report input, true duplicate, retry, injected I/O failure, and SIGKILL during materialization. A deterministic interprocess gate commits a conflicting row before the CLI's exclusive `flock`; another test proves a second process cannot obtain the lock during materialization. Explicit temporary roots and isolated HOME/XDG/TMPDIR were used; no target data was used.
- The source-selector launcher suite required a task-owned `.venv/bin/python` shim pointing at the candidate Core source because this fresh worktree had no environment and the real launcher strips `PYTHONPATH`. The shim was removed. This is source-candidate testing, **not installed/pinned dependency verification**. An earlier run without that shim failed solely at missing launcher interpreter; rerun above passed.
- `git diff --check` passed. Independent review: not performed; parent owns it.

## Blockers and deferred work

1. **Provider and pin:** candidate Core is under review and not published. After parent supplies the exact integrated, published Core SHA, update BBH `requirements.txt`, use the repository's `./setup.sh --install-python-deps` in the intended disposable checkout/environment, check the installed Core provenance/revision and `import_finding` availability, then rerun the seven focused modules above plus actual launcher CLI smoke using the installed dependency. Re-evaluate this implementation if the published API or FID exception contract differs. Do not merge, push, promote, or activate before these gates and independent review.
2. **Distinct manual ingest path:** `ManualHunter.ingest` still uses the old `check()` + `update_team_finding()` split. Synthetic actual CLI reproduction against the same candidate: an existing `fid=raw` collision made the first manual import fail after adding `D01`; the retry returned `Duplicate: D01` with no completed import. Its duplicate-comment semantics differ and were intentionally not changed in this narrowly delegated sync-reports patch. Parent must explicitly decide and address this separate entry point before claiming all report/manual imports are safe or promoting the overall collision fix. Existing orphan rows require manual reconciliation; this change does not recover them.

## Resume / decision gates

- **Exact resume:** parent reviews `origin/beta..fix/atomic-report-import`, resolves the manual-ingest issue and provider review, integrates/publishes Core, supplies the exact immutable SHA, then repins and verifies installed BBH. Remove this branch-local dossier during accepted beta integration.
- **Integration gate:** provider pin + installed smoke and focused tests + independent complete-diff review; no merge or push performed by this worker.
- **Activation / promotion:** separate parent-controlled decisions after verifying integrated beta and assessing the separate manual path. No runtime changed.
