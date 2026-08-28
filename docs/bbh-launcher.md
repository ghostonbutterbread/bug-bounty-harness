# BBH command launcher

`bbh` is the only command form for invoking a repository-owned BBH script from
a skill. Give it the script's repository-relative path; it resolves the physical
location of `scripts/bbh` and runs that path from the same checkout. A skill
therefore cannot load from one checkout and run a tool from another through an
absolute path or `HARNESS_ROOT` fallback.

## Commands

```bash
bbh agents/manual_hunter.py <program> --lane <lane> ...
bbh agents/me_ledger.py <arguments>
bbh agents/url_ingest.py <arguments>
bbh scripts/recon_bus.py <arguments>
bbh scripts/tool_run.py <arguments>
```

`bbh --root` prints the selected checkout. `bbh --print-command <path>` prints
the resolved executable without running it.

## Adding a runnable BBH skill

1. In the skill, reference the repository-owned script as
   `bbh <repository-relative-script-path> ...`.
2. Do not add a launcher registry entry, absolute checkout path, or
   `$HARNESS_ROOT` fallback.
3. Use normal relative links for skill-local reference files; `bbh` is only for
   executable files owned by this repository.

Reference-only skills need no command entry.

## Lane activation

The launcher intentionally does not use `HARNESS_ROOT`. Install or symlink the
`bbh` launcher from the selected lane's checkout into that lane's command path;
use `./setup.sh --install-dispatchers` when that command path is selected. A
beta agent's `bbh` must resolve to the beta checkout; a stable agent's `bbh`
must resolve to the stable checkout. The command is then identical in both
lanes.

`HARNESS_SHARED_BASE` remains the resolver for external shared program data.
