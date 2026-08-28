# BBH lane-safe launcher

## Intent

Replace repository-path commands in BBH skills with `bbh <tool> ...`. The
launcher resolves its own physical file location, so a symlink from a selected
lane runs only that checkout's repository-owned tools.

## Base and target

- Feature branch: `feat/bbh-lane-safe-launcher`
- Base: `beta` at `813fc6a1610646d52a8e5b2f774bbc7f69d21cd2`
- Intended integration target: `beta`

## Contract

- `bbh` has an explicit registry of supported repository-owned tools.
- It does not read `HARNESS_ROOT`.
- `bbh --root` and `bbh --print-command <tool>` expose the selected checkout
  without running a tool.
- Unknown tools fail closed.
- `HARNESS_SHARED_BASE` remains the external shared-data resolver.

## Scope

This foundation adds the dispatcher, installer hook, documentation, regression
tests, and migration of the highest-risk demonstrated command examples:
`manual-hunter`, `me-ledger`, `url-ingest`, and Recon Bus guidance. It does not
mass-migrate every historical `$HARNESS_ROOT` reference or activate/repoint any
runtime lane.

## Verification

Run `python3 tests/test_bbh_launcher.py`, direct launcher smoke commands, and
`bash -n setup.sh scripts/bbh`. Review the diff for residual hardcoded examples
outside this bounded migration scope.

## Activation boundary

A lane owner must install/symlink `bbh` from the intended beta or stable
checkout into that lane's command path. Promotion and Hoster checkout repair
remain separate, explicit operations.
