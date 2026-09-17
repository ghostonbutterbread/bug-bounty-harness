# Integration dossier: fix/dep-drift-warning

## Intent

Promote change proposal `CP-2026-09-17-bbh-dependency-drift-check`
(`~/Shared/change_proposals/2026-09-17-claude-bbh-dependency-drift-check.md`):
warn on stderr when `requirements.txt` is newer than the checkout's
`.venv/lib/python*/site-packages`, so manifest→environment drift surfaces as an
actionable message ("run ./setup.sh --install-python-deps") instead of a late
`ImportError` (observed: `PublicArtifactStore` import failure).

## Branch and target

- Feature branch: `fix/dep-drift-warning`
- Worktree: `/home/ryushe/worktrees/bbh-dep-drift-warning`
- Base: `origin/beta` at `ea3d50f`
- Intended target: `beta` (integration lane)

## Implemented contract

- `scripts/bbh.py`: new `dependency_drift_warning()` — mtime screen only
  (manifest newer than site-packages dir); suppressed by `BBH_SKIP_DEP_CHECK=1`;
  returns `None` on any `OSError` / missing pieces. `runtime_python()` prints the
  warning to stderr before dispatch. stdout and exit code untouched.
- `tests/test_bbh_launcher.py`: four e2e cases using a temp checkout with a
  copied real launcher, dummy tool, and fake venv python (echo JSON, exit 7):
  stale→warning + exit 7 preserved; in-sync→silent; suppressed→silent;
  missing site-packages→silent.

## Evidence

- `python3 -m pytest tests/test_bbh_launcher.py -q` → 14 passed.
- Full suite `tests/ -q` → 159 passed, 1 skipped, 2 failed. Both failures
  (`test_hoster_script_authority_uses_current_capability_not_machine_lists`,
  `test_runnable_skill_and_prompt_commands_do_not_select_a_checkout_directly`)
  reproduce on unmodified `origin/beta` ea3d50f (verified via stash round-trip);
  pre-existing, out of scope.

## Blockers

None. Pending: independent review subagent, then merge to beta and push.

## Next

Independent release-gate review → merge `fix/dep-drift-warning` into clean local
beta integration worktree → run focused checks → `git push origin beta` → retire
feature branch/worktree. Related: skill seed
`~/Shared/skill_seeds/2026-09-17-dependency-environment-sync.md` (ai-policies
lane) and papercut `PC-20260917-220123-533924d8`.
