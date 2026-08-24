# Bounty Storage Manifests And Handoffs

## Artifact Maps

Shared artifact maps are the first place agents should look for heavy bounty
artifacts. Prefer machine-readable maps:

```text
~/Shared/web_bounty/<program>/web/recon/artifacts/screenshots-map.json
~/Shared/web_bounty/<program>/web/recon/artifacts/javascript-map.json
~/Shared/web_bounty/<program>/web/recon/artifacts/proxy-flows-map.json
~/Shared/bounty_recon/<program>/apk/recon/artifacts/static-map.json
```

Human summaries can live in `artifact-map.md`; JSON maps are the agent source.

When following a pointer, check that the target exists. If missing, stale,
moved, deleted, or regenerated, update status instead of silently recreating
unrelated folders or trusting stale paths.

## Run Manifest

Every large run should leave a compact Shared manifest with:

- `run_id`, `program`, `tool_or_skill`, `host`, `started_at`, `finished_at`
- scope assumptions and input sources
- Shared output path
- heavy artifact root and scratch path
- surface/category path
- counts: inputs, fetched, reused, skipped, blocked, failed, parsed, packetized
- blocked/auth-required/redownload queues
- index paths and packet directories
- curated Shared lists updated
- cleanup/retention notes
- exact command, script, or tmux session to resume/regenerate

Prefer JSON for agents plus a short Markdown summary for humans.

## Trusted Promoters

Use a tool's native append/dedupe flow first when it owns one, then write a
Shared manifest or artifact-map pointer. `recon-ry` is an approved trusted
promoter; its tool-owned root files can remain canonical while Shared stores a
manifest/counts record when needed.

## Long-Running Runs

Long runs should use `/tmux`, a manifest under `~/.tmux_sessions/`, raw output
under `/mnt/bounty`, and a compact Shared manifest/artifact-map entry.

Useful watcher:

```bash
python3 ~/Shared/bounty_recon/_shared/scripts/bounty_run_watch.py --program <program> --update
```

## Archived Or Moved Programs

If a Shared program is archived or moved, leave a pointer stub:

```text
~/Shared/web_bounty/<program>/ARCHIVED.md
~/Shared/web_bounty/<program>/archive-manifest.json
```

or:

```text
~/Shared/bounty_recon/<program>/ARCHIVED.md
~/Shared/bounty_recon/<program>/archive-manifest.json
```

Treat those files as authoritative. Do not recreate a fresh Shared tree until
the archive manifest says where the active path is or Ryushe approves restore.

## Script Ownership

```text
Universal harness behavior -> /home/ryushe/projects/bug_bounty_harness/
Program-specific helper    -> ~/Shared/web_bounty/<program>/web/scripts/
                            or ~/Shared/bounty_recon/<program>/scripts/
General local utility      -> ~/scripts/
Shared wrappers/index      -> ~/Shared/bounty_recon/_shared/scripts/
```

Universal harness scripts belong in BBH first; Shared exposes them through a
small wrapper or index record.
