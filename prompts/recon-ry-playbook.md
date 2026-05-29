# Recon Ry Playbook

## Purpose

Use `recon-ry` as a Hoster-side, long-running recon producer. Ghost starts runs, records where they are running, and later ingests completed project directories into canonical recon artifact storage.

## Preflight

1. Confirm the target is in scope and high-volume recon is allowed.
2. Check Hoster connectivity:

```bash
ssh -i /home/ryushe/.ssh/hoster -o BatchMode=yes -o ConnectTimeout=5 ryushe@hoster 'hostname && whoami'
```

3. Check installation health:

```bash
ssh -i /home/ryushe/.ssh/hoster ryushe@hoster '$HOME/bin/recon-ry selftest && $HOME/bin/recon-ry check'
```

If tool dependencies are missing, report them. Do not block ingestion of already completed artifacts.

## Start Pattern

Start via the local wrapper so Hoster owns the long-running process:

```bash
python3 agents/recon_ry.py start <program> --url <scoped-domain-or-url> --profile full
```

The wrapper enforces saved scope before starting:

- if no saved scope exists for the program, it stops
- if the seed URL is not in scope, it stops
- `--allow-unscoped` is only for explicit Ryushe-approved exceptions

The wrapper writes `<remote-project>/rate_limit.conf` before launch. Default is conservative: `--rate-limit-rps 2`, `--timeout 300`. Increase only when the program policy allows it.

The command prints:

- PID
- remote log path
- remote project directory

Do not tail the process for the whole run. Save the PID/log/project path in notes or chat.

## Status Pattern

Use status for a short check only:

```bash
python3 agents/recon_ry.py status
```

If needed, inspect the last log lines manually on Hoster, but avoid turning this into a watcher.

## Ingest Pattern

After the run completes, ingest the project directory:

```bash
python3 agents/recon_ry.py ingest <program> \
  --source ryushe@hoster:/home/ryushe/bounties/<program> \
  --target <target-host>
```

The helper copies known `recon-ry` artifacts into:

```text
~/Shared/web_bounty/{program}/web/recon/recon-ry/{target}/runs/{YYYY-MM-DD}/{run_id}/
```

It writes `manifest.json` with counts for alive URLs, params, JavaScript files, secrets, dorks, and promotion state.

## Promotion Rule

Do not promote raw recon output into the findings ledger automatically.

Only create or update a finding after separate validation proves a bounty-grade issue, for example:

- exposed sensitive secret with verified impact and safe handling
- confirmed takeover condition
- deterministic sensitive file exposure
- authenticated or authorization-impacting behavior verified by a focused skill

## Notes

Use `/live-map`, `/access-control`, `/xss`, `/ssrf`, `/sqli`, or `/js` for follow-up testing based on the manifest and parsed artifacts.
