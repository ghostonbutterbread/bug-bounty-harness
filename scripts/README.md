# Harness Scripts

## `program_init.py`

- **Purpose:** Initialize a program’s canonical Bounty Core Shared lane and its
  non-secret mounted-artifact lane before first work or a stale-program refresh.
- **Inputs:** Program slug, required `--platform` for a scope pull or explicit
  `--skip-scope`; optional repeatable `--lane`; optional Shared/artifact roots.
- **Outputs:** Shared program layout/context, scope-derived web recon seeds,
  initialization manifest, artifact pointer, and mounted artifact directories.
- **Mutates:** Creates missing directories and front-door metadata only; never
  deletes or overwrites existing program files.
- **Example:** `bbh scripts/program_init.py example --platform bugcrowd --lane web --lane apk`
- **Preview:** `bbh scripts/program_init.py example --skip-scope --dry-run --json`
- **Verification:** `uv run --with pytest pytest tests/test_program_init.py -q`
- **Owner/scope:** Bug Bounty Harness / cross-program bootstrap.
- **Dependencies:** Python 3, Bounty Core import path, and network access only
  when `--platform` pulls scope.
- **Last verified:** 2026-08-18.
