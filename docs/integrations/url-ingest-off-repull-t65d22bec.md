# URL Ingest off-mode repull integration dossier

- **Status:** independently approved for beta integration only; integrated verification pending
- **Owner:** task t_65d22bec (PC-20261029-204345-fed8ef44)
- **Branch:** `fix/url-ingest-off-repull-t65d22bec`
- **Worktree:** `/home/ryushe/worktrees/bbh-url-ingest-off-repull-t65d22bec`
- **Base commit:** `f8a38feedc2326175bc216cb5ce3ec8f794f5c69`, freshly fetched `origin/beta`
- **Intended integration target:** `beta`
- **Last updated:** 2026-10-29
- **Owning feature branch/ref:** `fix/url-ingest-off-repull-t65d22bec`
- **Prior immutable recovery checkpoint:** `68fa1cded1db957bb53e991007a31ae74ed78c1e`; subsequent fix is in the commit carrying this dossier.
- **Feature implementation commit(s):** `44ee6803a4354959c506a649633915e5626f7271`
- **Inspiration:** `9bea5aceec1183eb0165f0b06ab4bd4efafb3cd1` in the divergent scope-consumer branch; only the analogous ingest default-resolution change was ported, not the branch or its other changes.

## Intent and implemented contract

`ingest()` previously defaulted `repull_scope=True` regardless of `scope_filter`. With missing synthetic scope, the programmatic `scope_filter="off"` path consequently attempted three platform subprocesses before accepting all URLs. The CLI already resolved its implicit default by mode and is not the source of this defect.

`ingest()` now resolves an omitted or `None` repull option to false only when `scope_filter` is exactly `off`; every other value retains beta's implicit repull. Prior filtering compares the exact value without normalization; API values such as `on`, `OFF`, `unknown`, and `None` are not newly rejected or normalized. Explicit true or false overrides the default. A pull is attempted only when saved scope is empty. With `off`, URLs remain unfiltered even when an explicit pull is requested; other modes still partition with saved or successfully pulled scope and preserve the existing unfiltered fallback when scope is missing or a pull fails. Thus out-of-scope URLs are rejected when scope exists, but the pre-existing missing-scope fallback does not guarantee that. This is an indexing/import setting, **not** permission for subsequent live target activity. CLI choices and aggregate defaults are unchanged. Import `scope_mode` and `scope_source` continue to describe the actual path, including the existing `saved_scope` source label when no pull was attempted even if scope is empty.

## Evidence and review

- On base `f8a38fe`, a temporary local synthetic URL and empty synthetic scope with `subprocess.run` intercepted produced three attempted platform calls; import `(accepted=1, rejected=0, mode=scope_filter_off, source=no_scope_after_pull)`.
- TDD: new `test_off_implicitly_never_runs_scope_puller` failed on base with the expected three mocked subprocess calls; after the change it passed. A matrix additionally covers implicit/default, explicit true/false in both modes, platform call count, import counts/mode/source and CLI option resolution. Existing suite covers saved-scope filtering and source recording.
- Full suite: `agents/test_url_ingest.py`: 36 passed, 13 subtests passed. No SQLite durability configuration was overridden. The test wrapper sets a scratch-only HOME and TMPDIR, checks source resolves to this worktree, denies `socket` and `connect` with kernel seccomp (both denials tested), and blocks actual subprocess creation; explicit mock tests intercept `subprocess.run`. Synthetic `.example.test` inputs only; no real target or network.
- Reproduce using the task scratch wrapper: `env BH_AGENT_SCRATCH=/home/ryushe/.hermes/profiles/bugfix/cache/scratch PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" /usr/bin/python3 /home/ryushe/.hermes/profiles/bugfix/cache/scratch/bbh_offline_pytest.py -q agents/test_url_ingest.py` from the feature worktree. Wrapper is ephemeral, not a committed test fixture; a reviewer must recreate equivalent seccomp and subprocess guards if scratch has expired.
- Independent reviewer blocked `68fa1cd`: API `on` with missing scope and a successful pull was silently skipped, adopting both synthetic URLs instead of filtering. New `test_on_implicitly_pulls_missing_scope_and_rejects_out_of_scope` failed on `68fa1cd` (zero calls, 2 accepted) and passes after the fix (one mocked call, 1 accepted / 1 rejected; DB contains only in-scope host). The reviewer comparison confirms base and fixed feature both pull and filter for `on`.
- Re-run after fix: 40 passed, 22 subtests (URL Ingest plus portable import paths), under the same verified seccomp/subprocess guard and normal SQLite durability. The reviewer's 36-case beta/feature matrix, with its obsolete `on` expectation corrected, plus its successful-pull comparison: 37 passed, one intentional old-off-red case deselected. Matrix covers saved/missing scope, off/auto/on, omitted/true/false overrides, failed pulls and recorded provenance. Additional suite subtests cover unknown/uppercase/None API modes and CLI rejection of unsupported modes. Inputs and mocked scope are synthetic only; no live target.
- Base fixture hash matches `git show f8a38fe:agents/url_ingest.py` SHA-256 `aa756575371400ee4ef170d7b56a7b217393894bdbc105a43ccad3a09e7f5827`; guarded tests confirmed feature import resolves to this worktree. Review matrix: `/home/ryushe/.hermes/profiles/bugfix/cache/scratch/bbh-release-gate-t65d22bec/test_independent.py` (ephemeral). Command: replace test path in wrapper above, append `-k 'not old_off_expected_red'`.
- Prior independent review: BLOCK at `68fa1cd`; corrected in `0999bfc7264a6953cbcdedc0b3725e313b18b686`.
- Fresh independent review APPROVE beta-only at exact implementation tip `0999bfc7264a6953cbcdedc0b3725e313b18b686`, against freshly fetched beta `f8a38feedc2326175bc216cb5ce3ec8f794f5c69`. Reviewer reran 40 tests + 22 subtests, the 36-case matrix plus successful-pull check, and 15 additional checks under verified network and process denial with normal SQLite durability. Review receipt: `/home/ryushe/.hermes/profiles/bugfix/cache/delegation/live/deleg_50a8786c/task-0.log` (ephemeral). The release integrator independently fetched the same beta and inspected the code diff. Existing missing-scope unfiltered fallback and explicit repulls remain intentional.

## Blockers and deferred work

- Integrated-tree guarded suite, matrix, provenance and clean-diff checks are required before publishing beta. Stop on drift, conflicts or unexpected failures. No live network/target testing is requested.

## Interruption / resume handoff

- **Owning feature branch/ref:** `fix/url-ingest-off-repull-t65d22bec`
- **Prior immutable recovery checkpoint:** `68fa1cded1db957bb53e991007a31ae74ed78c1e`; subsequent fix is in the commit carrying this dossier.
- **Feature implementation commit(s):** `44ee6803a4354959c506a649633915e5626f7271`
- **Exact resume point:** fetch reviewed feature including this dossier-only decision commit into the designated clean beta clone, merge without committing, remove this new dossier, rerun guarded integrated checks, then publish only if every gate passes.
- **Working-tree state at handoff:** clean after the dossier checkpoint commit; verify with `git status`.

## Decision gates

- **Integration:** reviewed beta-only; fresh beta and guarded integrated tests required; remove this branch-local dossier during integration.
- **Activation / promotion:** not authorized or attempted in this task.

## Decision record

- 2026-10-29 — reproduced API-only discrepancy on freshly fetched beta; implemented and locally verified the narrowly scoped fix.
- 2026-10-29 — independent review approved exact feature `0999bfc7264a6953cbcdedc0b3725e313b18b686` for beta only; integration remains subject to current-beta and integrated verification gates.
