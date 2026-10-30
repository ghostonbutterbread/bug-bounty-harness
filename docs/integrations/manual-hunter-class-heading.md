# Manual-hunter Class heading integration dossier

- **Status:** blocked pending independent review and clarification/resolution of per-report FID validation
- **Owner / task:** Hermes subagent, BBH t_4c4f1212 / PC-20260929-001815-14a98db0
- **Branch / worktree:** `fix/manual-hunter-class-heading` / `/home/ryushe/worktrees/bbh-manual-hunter-class-heading`
- **Base:** `origin/beta` `47b3aff4c102bc6987ce747877d08409761b3130`, re-fetched 2026-10-29
- **Intended integration target:** `beta` (integration not authorized here)
- **Prior immutable checkpoint:** `4c899d46d82802cd7bf8c075ac789ba9e8715f0b`; initial implementation `204db4c25c4f2cd9cd463305f2e3f03291807e24`.
- **Canonical references:** `agents/manual_hunter.py`, `agents/sync_reports.py`, corresponding tests, `docs/manual-hunter-class-input.md`. Prior metadata fix `3fa84b8` is an ancestor of base.

## Intent and boundaries

Correct class identity and conflict handling for direct notes and structured multi-finding reports. Use only disposable synthetic fixtures. No real findings, target traffic, push, integration, stable, Hoster, activation, or closure. Stable propagation requires a separate decision.

## Contract and compatibility

The class parser is shared by direct and sync import and honors explicit `unknown`, open vocabulary, aliases and normalized agreement. It excludes fenced metadata and stops class headings at fields, headings, fences and EOF. Plain unmarked heading values are now single tokens; multiword values must be marked bold/list or given as a `Class:` field. Ambiguous heading prose is rejected with an actionable diagnostic, not guessed. Fenced contents no longer contribute to keyword class inference; absent/empty explicit class still infers, with the existing warning in manual hunter. See `docs/manual-hunter-class-input.md` for syntax and exit semantics. Direct CLI catches class decision errors without a traceback.

Structured sync validates every block's class and tier decision before returning candidates for any write; independently selected tiers no longer bypass block conflict checks. Explicit values and inference are scoped to each block; flexible metadata is merged per block. Different report files are not a batch transaction. The importer still performs mutating ledger reservation/FID collision checks sequentially after candidate validation, and does not roll back I/O failures or FID collisions. Thus it does **not** guarantee all possible validations or atomic writes across a report; do not represent it as doing so.

## Evidence and review

- Independent review of `4c899d46` blocked on cross-tier conflict bypass, heading class loss/unknown overwrite, unsafe heading parsing and direct CLI traceback; see `/home/ryushe/.hermes/profiles/bugfix/cache/delegation/live/deleg_a5e5e071/task-0.log`.
- TDD reds observed for mixed-tier class conflict (incorrect exit 0), per-block explicit unknown/custom headings (both inferred DOM XSS), prose/fence/markup parsing, direct CLI traceback, fake fenced finding, inference from a fenced Class example, and structured flexible metadata. Each corresponding focused test passed after repair.
- Synthetic real-ledger tests exercise mixed-tier two-finding class conflict without a report write, explicit unknown/custom heading import, separate-file partial batch with exit 1, and actual subprocess CLI duplicate link and conflict diagnostic. No real program ledger was used.
- Full command: `PYTHONPATH="$PWD:$TMPDIR/manual-class-core" HOME="$TMPDIR/manual-class-run-home" /usr/bin/python3 "$TMPDIR/manual-class-netdeny.py" /usr/bin/python3 -m unittest agents.test_manual_hunter agents.test_sync_reports -q` — **95 passed**, with expected inference warnings. Seccomp inherited by subprocesses denies sockets; a socket attempt returned EPERM. `unshare -n` was unavailable in the earlier run.
- `requirements.txt` pins Bounty Core `6c36ee88a60073e1b687ec32deeade24ffafdd4f`; `git archive` bytes for all 18 exported `bounty_core` files matched the scratch import. Provenance: manual and sync modules from this worktree, core from `$TMPDIR/manual-class-core`.

## Blockers and next action

1. User requested validation of all findings before any report writes. Class/tier checks meet that narrow prewrite condition, but `VersionedFindingsLedger.check` reserves an FID and persists as it goes; a later same-report FID collision can leave earlier entries. A true preflight needs a non-mutating canonical ledger validation operation and concurrency semantics, or an explicit owner decision accepting current narrower scope. Reproduce with `agents.test_sync_reports.TestSyncReports.test_real_ledger_fid_collision_continues_import_and_returns_nonzero`. Do not claim full per-report validation until resolved.
2. Fresh independent review of this new exact tip, full offline suite rerun, and current beta reconciliation are still required. No integration, publication, activation or closure authorized.

## Interruption / decision record

- Resume on the owning feature branch at its new commit; verify its exact SHA and diff against `4c899d46` and base. The previous commit is a recoverable immutable checkpoint; inspect later feature commits separately.
- 2026-10-29: Independent review identified blockers. Repair developed with focused red/green tests. No integration attempted. Deferred FID preflight and fresh review remain blockers.
