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
bbh scripts/safety_incident.py --program <program> --lane <lane> --profile <absolute-path-to-context/target_profile.json> record --producer <producer> --run-id <run-id> --category <category> --severity <unknown|low|medium|high|critical> --action <action> --subject <subject> --impact <impact> --containment <containment> [--no-notify]
```

The safety incident command forwards to pinned Bounty Core. Record promptly
after stopping/containing an unsafe action, with factual, non-secret fields;
`--no-notify` records without a Discord delivery attempt. The provider defaults
severity to `unknown` for older callers; choose an observed urgency level for
colored Discord embeds. It prints the saved ID and short action to the terminal
before attempting delivery. The profile must be
the actual selected lane's `context/target_profile.json`; its program, family,
lane, location and canonical root must agree with the command. The client derives
the shared base from that profile and never falls back to `~/Shared`, cwd, or an
environment variable. Supply `--family` for non-web families; optional `--root`
must resolve to the same lane. For local verification use a disposable profile
and shared base with `--no-notify`. This explicit reporting
channel does not intercept requests, detect incidents, or stop actions for you.
Only this CLI loads a fallback credential: when `DISCORD_SAFETY_WEBHOOK_URL` is
unset, it reads `$HOME/.config/bounty-core/safety-webhook-url` after profile
validation. Provision the per-host file outside the repository, owned by the
running user, as a regular non-symlink file with owner-only permissions
(mode 0600 recommended). Its contents must be a single Discord webhook URL,
optionally ending in one newline. Do not put the URL in a command,
Shared artifact, Git, or incident fields. An explicit environment setting wins,
including an empty one. If the file is absent, invalid, or insecure, the CLI
warns generically without printing it; `record` still persists and returns the
provider's `not-configured` receipt and exit status 1. Inspect the incident ID
before retrying `notify`, which can duplicate an ambiguous delivery.
See [`scripts/README.md`](../scripts/README.md) for its mutation boundary.

`bbh --root` prints the selected checkout. `bbh --print-command <path>` prints
the resolved path of an existing repository-owned file without running it; this
diagnostic may resolve non-executable files such as a playbook. It does not
assert that the path is executable.

## Adding a runnable BBH skill

1. In the skill, reference the repository-owned script as
   `bbh <repository-relative-script-path> ...`.
2. Do not add a launcher registry entry, absolute checkout path, or
   `the active BBH checkout` fallback.
3. Use normal relative links for skill-local reference files. Normal `bbh`
   dispatch runs only supported repository-owned executables; use the read-only
   `--print-command` diagnostic to locate another repository-owned file.

Reference-only skills need no command entry.

## Lane activation

The launcher intentionally does not use `HARNESS_ROOT`. Install or symlink the
`bbh` launcher from the selected lane's checkout into that lane's command path;
use `./setup.sh --install-dispatchers` when that command path is selected. A
beta agent's `bbh` must resolve to the beta checkout; a stable agent's `bbh`
must resolve to the stable checkout. The command is then identical in both
lanes.

`HARNESS_SHARED_BASE` remains the resolver for external shared program data.

## Dependency drift warning

The launcher compares the manifest's modification time with its checkout-local
environment as a screen, not proof of dependency drift. A fresh checkout or a
restored environment may trigger it even if revisions match. For the pinned
Bounty Core revision, compare the manifest with the installed VCS commit:

```bash
root="$(bbh --root)"
"$root/.venv/bin/python" -c 'import importlib.metadata as m,json; d=m.distribution("bounty-core"); u=json.loads(d.read_text("direct_url.json")); print(u.get("vcs_info",{}).get("commit_id","unknown"))'
```

Read `requirements.txt` in that same root and compare its pinned revision.
An absent distribution or missing VCS metadata needs investigation rather than
being treated as a match. A matching Bounty Core revision does not establish
that every other dependency matches; compare the relevant installed packages
with the manifest too. If the actual environment is mismatched, run the
checkout's documented installer from that root:

```bash
(cd "$(bbh --root)" && ./setup.sh --install-python-deps)
```

The mtime warning may persist after comparison because it does not record
verification. `BBH_SKIP_DEP_CHECK=1` suppresses this screen for an individual
invocation; it is not proof that the environment is current.
