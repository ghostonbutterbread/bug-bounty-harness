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

This migration routes every runnable BBH command documented in `skills/**/SKILL.md`
and `prompts/*.md` through `bbh <repository-relative-path>`. It self-anchors the
remaining local BBH imports, replaces the fixed Hoster checkout commands with a
lane-installed Hoster `bbh`, and removes conventional Bounty Core/Bounty Tools
source fallbacks. Bounty Tools remains an optional standalone utility rather
than a lane-bound BBH dependency.

Bounty Core is an ordinary BBH Python dependency. Each BBH checkout installs
the pinned Git revision in `requirements-bounty-core.txt` into its own `.venv`
through `./setup.sh --install-python-deps`; the lane dispatcher runs Python
tools with that checkout-local interpreter. BBH never uses Aiskillsync state,
`$BOUNTY_CORE_ROOT`, sibling paths, `~/projects`, installed packages, or CWD to
select Bounty Core.

Stable and beta BBH may share the same Bounty Core Git pin while retaining
separate `.venv` directories. Update the pin only through a reviewed change to
the dependency manifest, then reinstall it in each active BBH checkout.

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
