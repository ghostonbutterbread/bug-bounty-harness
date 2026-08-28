# BBH command launcher

`bbh` is the only command form for invoking repository-owned BBH tools from a
skill. It resolves the physical location of `scripts/bbh` and dispatches from
that checkout. A skill therefore cannot load from one checkout and run a tool
from another by falling back to an unqualified repository path.

## Commands

```bash
bbh manual-hunter <program> --lane <lane> ...
bbh me-ledger <arguments>
bbh url-ingest <arguments>
bbh recon-bus <arguments>
bbh tool-run <arguments>
```

`bbh --root` prints the selected checkout; `bbh --list` prints registered tool
names; `bbh --print-command <tool>` prints the resolved executable without
running it.

## Adding a runnable BBH skill

1. Add its stable command name and repository-relative executable path to
   `TOOLS` in `scripts/bbh.py`.
2. Use `bbh <tool> ...` in the skill instead of a checkout path or
   `$HARNESS_ROOT`.
3. Add a focused launcher test if the dispatch contract is non-trivial.

Reference-only skills do not need an entry.

## Lane activation

The launcher intentionally does not use `HARNESS_ROOT`. Install or symlink the
`bbh` launcher from the selected lane's checkout into that lane's command path.
A beta agent's `bbh` must resolve to the beta checkout; a stable agent's `bbh`
must resolve to the stable checkout. The command is then identical in both
lanes.

`HARNESS_SHARED_BASE` remains the resolver for external shared program data.
