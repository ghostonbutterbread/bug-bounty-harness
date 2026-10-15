# BBH command launcher

`bbh` is the lane-safe command form for **migrated** repository-owned BBH
script invocations in a skill. Give it the script's repository-relative path;
it resolves the physical location of `scripts/bbh` and runs that path from the
same checkout. A migrated command therefore cannot load from one checkout and
run a tool from another through an absolute path or `HARNESS_ROOT` fallback.

Legacy skills still contain direct relative or `the active BBH checkout` commands. They
are not covered by this guarantee and must be migrated before being treated as
lane-safe.

## Commands

```bash
bbh agents/manual_hunter.py <program> --lane <lane> ...
bbh agents/me_ledger.py <arguments>
bbh agents/url_ingest.py <arguments>
bbh scripts/recon_bus.py <arguments>
bbh scripts/tool_run.py <arguments>
bbh scripts/safety_incident.py --program <program> --lane <lane> record --producer <producer> --run-id <run-id> --category <category> --action <action> --subject <subject> --impact <impact> --containment <containment> [--no-notify]
```

The safety incident command forwards to pinned Bounty Core. Record promptly
after stopping/containing an unsafe action, with factual, non-secret fields;
`--no-notify` records without a Discord delivery attempt. For local verification
pass `--root <temporary-shared-base>` before `record`. This explicit reporting
channel does not intercept requests, detect incidents, or stop actions for you.
See [`scripts/README.md`](../scripts/README.md) for its mutation boundary.

`bbh --root` prints the selected checkout. `bbh --print-command <path>` prints
the resolved executable without running it.

## Adding a runnable BBH skill

1. In the skill, reference the repository-owned script as
   `bbh <repository-relative-script-path> ...`.
2. Do not add a launcher registry entry, absolute checkout path, or
   `the active BBH checkout` fallback.
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
