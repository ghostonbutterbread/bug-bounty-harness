# Browser provisioner INSERT repair integration dossier

- **Status:** review-ready locally; not integrated or activated
- **Owner:** Hermes bugfix subagent
- **Branch / owning ref:** `fix/browser-provisioner-insert`
- **Worktree:** `/home/ryushe/projects/bug_bounty_harness/browser-provisioner-insert`
- **Base commit:** `8e82041f0808d3a2ead8d7bfafb9c589a4d6bd9a` (`origin/beta`, fetched 2026-09-23)
- **Intended integration target:** `beta`
- **Last updated:** 2026-09-23
- **Latest immutable recovery checkpoint:** branch tip after commit (verify with `git rev-parse HEAD`)
- **Feature implementation commit(s):** branch tip after commit (verify with `git log -1`)
- **Inspiration / canonical references:** appended `auth_domain` on old manager SQLite layout; fresh CREATE layout places it fifth.

## Intent and implemented contract

`start()` previously issued a positional 16-value `INSERT INTO browsers VALUES (...)`. Fresh databases put `auth_domain` fifth, but `db()` appends it last on historical databases. The SQL now names all sixteen columns in the value order already used by `start()`, retaining both layouts and all current values. No migration, rewrite, or deletion of existing manager records is included.

## Evidence and review

- Red regression before repair: fresh schema passed; appended schema produced a timestamp in `auth_domain`, launch path in `state`, and displaced other fields.
- Green: `python -c 'import os,pytest; fd=os.open(os.environ["TMPDIR"],os.O_RDONLY|os.O_DIRECTORY); raise SystemExit(pytest.main(["-q","--basetemp=/proc/self/fd/%d/p"%fd,"agents/test_browser_provisioner.py","agents/test_browser_lease_recovery.py","agents/test_browser_startup_diagnostics.py"]))'` — 48 passed. Short `/proc/self/fd` alias addresses an unrelated AF_UNIX fixture path-length failure while physical temp files remain in configured scratch.
- Regression invokes the real `db()` ALTER and `start()` recording path in fresh and appended layouts, asserts every stored semantic column, checks domain selection, and retains a representative previously shifted row unchanged. Browser/systemd/lease edges are mocked; this is not a live-browser acceptance test.
- `git diff --check` clean before commit. Descendant `feat/browser-legacy-auto-migration` is based on `beta` and has the same positional insert; this commit is for later merge into beta and then descendant, not a duplicate edit here.
- Independent review, beta integration, Hoster validation and activation: not performed in this bounded task.

## Blockers and deferred work

- **Existing malformed manager records:** SQL repair only prevents new corruption. Historical shifted rows can have numeric `auth_domain`, path-valued `state`, displaced `unit`/`profile_dir`/`launch_file` and timestamps. Domain-filtered selection misses them; normal cleanup may also miss them. Do not infer inactive ownership from missing selection or auto-repair/delete them. Reconcile exact canonical leases, units, processes, receipts and profile paths under a separate reviewed safety procedure before Hoster rollout.
- **Activation evidence:** no Hoster touch authorized here. After independent review and merge into beta and descendant, prove a disposable real-browser start on the appended schema, then perform the separately gated read-only audit and rollout checks. Do not activate based on unit-test success alone.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/browser-provisioner-insert`
- **Latest immutable recovery checkpoint:** branch tip after commit
- **Exact resume point:** independently review the branch diff, verify upstream beta, then integrate through the parent workflow; reconcile historical records separately.
- **Working-tree state at handoff:** clean after commit (verify).

## Decision gates

- **Integration gate:** independent review, current beta reconciliation, focused rerun. Parent owns merge; no merge/push here.
- **Activation / cohort gate:** real disposable browser fixture and historical-row safety proof on Hoster before rollout.
- **Promotion gate:** separate review and authorization.

## Decision record

- 2026-09-23 — isolated beta-ancestor fix prepared; historical data explicitly left untouched.
