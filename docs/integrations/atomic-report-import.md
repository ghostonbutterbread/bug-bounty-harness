# Atomic report import integration dossier

- **Status:** blocked pending Core release, consumer pin, installed verification and independent review
- **Owner:** delegated BBH sync importer worker; parent owns integration
- **Branch:** `fix/atomic-report-import`
- **Worktree:** `/home/ryushe/worktrees/bbh-atomic-report-import`
- **Base commit:** `4ba241ce9859e7ee4964566e54976aeb032336fd` (fresh `origin/beta`)
- **Intended integration target:** `beta` (eventual authorized promotion to `master` is separate)
- **Last updated:** 2026-11-17
- **Owning feature branch/ref:** `fix/atomic-report-import`
- **Latest immutable recovery checkpoint / manual implementation:** `3b449721be66d5367f613505b5e56db178340209`; branch tip contains a later dossier-only handoff. Earlier sync implementation: `6329b0f4ea48281726acfe42ec064cbfd5bbd85b`.
- **Inspiration / canonical reference:** Core candidate `/home/ryushe/worktrees/core-raw-collision-minimal` at `266d0da8d7cc21bfbd5165667b2bf0aa734bb121`, unreviewed/unpublished; `VersionedFindingsLedger.import_finding(..., packet_mode='evidence_only')`.

## Intent and implemented contract

`sync_reports` and `ManualHunter.ingest` formerly called `check()` (which reserves) and then separately materialized the finding. On a pre-existing raw/packet collision, the second operation failed after the reservation, causing the next run to call the incomplete record a duplicate. Both now use Core's locked check/reserve/materialize operation. Manual completed duplicates preserve the existing nonzero return, output and optional comment behavior without adding a sighting. Sync completed duplicates remain skipped; FID conflicts retain the previous nonzero, continue-and-summarize behavior. Only Core's exact `finding FID already assigned: ` ValueError prefix is classified as an FID conflict in sync; other ValueErrors and I/O errors propagate as failures. This prefix is the candidate's current contract, not a typed exception. No dependency pin changed.

The Core operation marks interrupted materializations as pending and retries them; it cannot identify or automatically repair pre-existing partial reservations created by the old split path. Do not claim all old rows are repaired. Core states packet/index I/O is not fully transactional and the lock coordinates only cooperating writers.

## Evidence and review

- Red/green: `agents.test_sync_reports_atomic.AtomicReportImportCLI.test_raw_collision_fails_without_reservation_then_retry_imports` failed on the original BBH source because ledger bytes changed after a raw collision; passed after the consumer fix.
- Final focused run: 167 tests passed using `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD:/home/ryushe/worktrees/core-raw-collision-minimal" ... python -m unittest agents.test_sync_reports agents.test_sync_reports_atomic agents.test_report_source_cli agents.test_manual_hunter agents.test_report_checker agents.test_report_checker_exceptional agents.test_finding_report -q`. Log: `/home/ryushe/.hermes/cache/scratch/bbh-atomic-focused-final.log`; scratch is ephemeral. Six expected manual-hunter class-inference warnings appeared.
- Real CLI synthetic fixtures cover raw and FID collisions, byte-preserving non-reservation, ordinary canonical raw/report input, true duplicate, retry, injected I/O failure, and SIGKILL during materialization. A deterministic interprocess gate commits a conflicting row before the CLI's exclusive `flock`; another test proves a second process cannot obtain the lock during materialization. Explicit temporary roots and isolated HOME/XDG/TMPDIR were used; no target data was used.
- The source-selector launcher suite required a task-owned `.venv/bin/python` shim pointing at the candidate Core source because this fresh worktree had no environment and the real launcher strips `PYTHONPATH`. The shim was removed. This is source-candidate testing, **not installed/pinned dependency verification**. An earlier run without that shim failed solely at missing launcher interpreter; rerun above passed.
- Manual-ingest red/green: `agents.test_manual_hunter_atomic.AtomicManualImportCLI.test_raw_collision_preserves_ledger_and_retry_adds` failed on the original source because ledger bytes changed, then passed with `import_finding`.
- Additional isolated manual and combined tests: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD:<immutable-Core-archive>" python -m unittest agents.test_manual_hunter_atomic agents.test_manual_hunter agents.test_sync_reports agents.test_sync_reports_atomic agents.test_report_checker agents.test_report_checker_exceptional agents.test_finding_report -q` passed 160 tests; six expected class-inference warnings. Core archive created with `git archive 266d0da8d7cc21bfbd5165667b2bf0aa734bb121`; imports confirmed from the archive, not the concurrently edited Core checkout. Launcher `agents.test_report_source_cli` passed 13 tests separately using the source shim described above. CLI fixtures cover add, duplicate/optional comment and unchanged sightings, raw collision/retry, competing process before lock, lock held during materialization, SIGKILL/retry, propagated injected I/O error/retry, and actual `agents.finding_report` registration of the manually generated packet.
- `git diff --check` passed. Independent review: not performed; parent owns it and should request the same prior reviewer for these corrections.

## Blockers and deferred work

1. **Provider and pin:** candidate Core is under review and not published. After parent supplies the exact integrated, published Core SHA, update BBH `requirements.txt`, use the repository's `./setup.sh --install-python-deps` in the intended disposable checkout/environment, check the installed Core provenance/revision and `import_finding` availability, then rerun `agents.test_manual_hunter_atomic` and the seven focused modules above plus actual launcher CLI smoke using the installed dependency. Re-evaluate both consumers if the published API or FID exception contract differs. Do not merge, push, promote, or activate before these gates and independent review.
2. **Legacy reservations:** Core cannot distinguish old unmarked split-path partial rows from legitimate completed duplicates; inventory and manually reconcile affected old rows rather than silently claiming recovery.

## Resume / decision gates

- **Exact resume:** parent has the original independent reviewer review the manual-ingest correction and tests, resolves provider review, integrates/publishes Core, supplies the exact immutable SHA, then repins and verifies installed BBH. Remove this branch-local dossier during accepted beta integration.
- **Integration gate:** provider pin + installed smoke and focused tests + independent complete-diff review; no merge or push performed by this worker.
- **Activation / promotion:** separate parent-controlled decisions after verifying integrated beta and assessing legacy rows. No runtime changed.
