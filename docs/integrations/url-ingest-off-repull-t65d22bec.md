# URL Ingest off-mode repull integration dossier

- **Status:** feature; independent review pending
- **Owner:** task t_65d22bec (PC-20261029-204345-fed8ef44)
- **Branch:** `fix/url-ingest-off-repull-t65d22bec`
- **Worktree:** `/home/ryushe/worktrees/bbh-url-ingest-off-repull-t65d22bec`
- **Base commit:** `f8a38feedc2326175bc216cb5ce3ec8f794f5c69`, freshly fetched `origin/beta`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** `fix/url-ingest-off-repull-t65d22bec`
- **Latest immutable recovery checkpoint:** none yet; will be filled after implementation checkpoint
- **Feature implementation commit(s):** none yet
- **Inspiration:** `9bea5aceec1183eb0165f0b06ab4bd4efafb3cd1` in the divergent scope-consumer branch; only the analogous ingest default-resolution change was ported, not the branch or its other changes.

## Intent and implemented contract

`ingest()` previously defaulted `repull_scope=True` regardless of `scope_filter`. With missing synthetic scope, the programmatic `scope_filter="off"` path consequently attempted three platform subprocesses before accepting all URLs. The CLI already resolved its implicit default by mode and is not the source of this defect.

`ingest()` now resolves an omitted or `None` repull option to false for `off` and true for `auto`. Explicit true or false overrides this default in either mode. A pull is attempted only when saved scope is empty. With `off`, URLs remain unfiltered even when an explicit pull is requested; `auto` still partitions with saved or successfully pulled scope and preserves the existing unfiltered fallback when scope is missing. This is an indexing/import setting, **not** permission for subsequent live target activity. Existing aggregate defaults and saved-scope handling are unchanged. Import `scope_mode` and `scope_source` continue to describe the actual path, including the existing `saved_scope` source label when no pull was attempted even if scope is empty.

## Evidence and review

- On base `f8a38fe`, a temporary local synthetic URL and empty synthetic scope with `subprocess.run` intercepted produced three attempted platform calls; import `(accepted=1, rejected=0, mode=scope_filter_off, source=no_scope_after_pull)`.
- TDD: new `test_off_implicitly_never_runs_scope_puller` failed on base with the expected three mocked subprocess calls; after the change it passed. A matrix additionally covers implicit/default, explicit true/false in both modes, platform call count, import counts/mode/source and CLI option resolution. Existing suite covers saved-scope filtering and source recording.
- Full suite: `agents/test_url_ingest.py`: 36 passed, 13 subtests passed. No SQLite durability configuration was overridden. The test wrapper sets a scratch-only HOME and TMPDIR, checks source resolves to this worktree, denies `socket` and `connect` with kernel seccomp (both denials tested), and blocks actual subprocess creation; explicit mock tests intercept `subprocess.run`. Synthetic `.example.test` inputs only; no real target or network.
- Reproduce using the task scratch wrapper: `env BH_AGENT_SCRATCH=/home/ryushe/.hermes/profiles/bugfix/cache/scratch PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" /usr/bin/python3 /home/ryushe/.hermes/profiles/bugfix/cache/scratch/bbh_offline_pytest.py -q agents/test_url_ingest.py` from the feature worktree. Wrapper is ephemeral, not a committed test fixture; a reviewer must recreate equivalent seccomp and subprocess guards if scratch has expired.
- Independent review: pending parent.

## Blockers and deferred work

- Independent review and current-beta reconciliation are required before integration. Parent owns these gates. Re-fetch `origin/beta`, inspect the feature diff, rerun the guarded URL Ingest suite on the reviewed source and resolve any divergence. No live network/target testing is requested.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/url-ingest-off-repull-t65d22bec`
- **Latest immutable recovery checkpoint:** none yet
- **Feature implementation commit(s):** none yet
- **Exact resume point:** review the feature diff and guarded test evidence; parent handles review and integration.
- **Working-tree state at handoff:** see Git status and later checkpoint update.

## Decision gates

- **Integration:** parent review, fresh beta and guarded tests; remove this branch-local dossier during integration.
- **Activation / promotion:** not authorized or attempted in this task.

## Decision record

- 2026-10-29 — reproduced API-only discrepancy on freshly fetched beta; implemented and locally verified the narrowly scoped fix.
