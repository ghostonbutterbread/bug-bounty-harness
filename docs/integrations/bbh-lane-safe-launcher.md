# BBH lane-safe launcher

## Intent

Replace repository-path commands in BBH skills with
`bbh <repository-relative-script-path> ...`. The launcher resolves its own
physical file location, so a symlink from a selected lane runs only that
checkout's repository-owned tools.

## Base and target

- Feature branch: `fix/portable-lane-context`
- Base: `beta` at `d4c8b29210eee1963450a3bf030c8da9d8a75429`
- Intended integration target: `beta`
- Companion integration: aiskillsync's `feat/portable-lane-context` emits the
  selected checkout receipt; this BBH change remains usable without aiskillsync.

## Contract

- `bbh` accepts any repository-relative Python or executable-script path; it has
  no per-tool registry.
- It does not read `HARNESS_ROOT`.
- `bbh --root` and `bbh --print-command <path>` expose the selected checkout
  without running a tool.
- Absolute paths and paths escaping the repository fail closed.
- `HARNESS_SHARED_BASE` remains the external shared-data resolver.

## Scope

This migration routes the audited runnable BBH commands in `skills/**/SKILL.md`
and `prompts/*.md` through `bbh <repository-relative-path>`, while the adjacent
`docs/bbh-launcher.md` inventories remaining legacy direct-relative or
`HARNESS_ROOT` routes outside this bounded change. It self-anchors the migrated
local BBH imports, replaces the fixed Hoster checkout commands with a
lane-installed Hoster `bbh`, and removes conventional Bounty Core/Bounty Tools
source fallbacks. Bounty Tools remains an optional standalone utility rather
than a lane-bound BBH dependency.

Bounty Core is an ordinary BBH Python dependency. Each BBH checkout installs the
published Core `beta` revision `fc361eca86f9c86acb357e1b9ce6426bc44aef83`
(including stale-reclaim repair `2da1e22d381e6c8c4fad1b2bfdb21692ae398d04`) from
`requirements-bounty-core.txt` into its own `.venv` through
`./setup.sh --install-python-deps`; the lane dispatcher runs Python tools with
that checkout-local interpreter. BBH never uses Aiskillsync state,
`$BOUNTY_CORE_ROOT`, sibling paths, `~/projects`, installed packages, or CWD to
select Bounty Core.

Stable and beta BBH may use separate `.venv` directories while consuming the
same pinned Core revision. Changing Core requires a reviewed BBH manifest update
and setup rerun in each active checkout.

## Verification

Run `python3 tests/test_bbh_launcher.py`, direct launcher smoke commands, and
`bash -n setup.sh`. The suite covers physical symlink resolution, foreign
`HARNESS_ROOT` isolation, and installation of `bbh`, `tool-run`, and
`recon-bus` into a temporary lane command path. Review the diff for residual
hardcoded examples outside this bounded migration scope.

## Activation boundary

A lane owner must install/symlink `bbh` from the intended beta or stable
checkout into that lane's command path. Promotion and Hoster checkout repair
remain separate, explicit operations.

## Skill-audit follow-up

- Source branch: `fix/skill-command-audit`; base and target: `beta` at
  `4809212`.
- The 89 canonical `SKILL.md` files were audited after beta activation. This
  follow-up removes checkout-selection, ambient `PYTHONPATH`, machine-local
  helper, and cwd-dependent sync guidance that could bypass the launcher
  contract.
- The static command-safety regression rejects those stale guidance forms and
  validates documented `bbh` targets.
- Verification: `python3 -m unittest -v tests.test_skill_command_lane_safety
  tests.test_migrated_skill_commands`.
