# Recon Ry Playbook

## Purpose

Use `recon-ry` as a Hoster-side, long-running recon producer and durable recon location. Ghost starts runs, records where they are running, and teaches agents where to read the resulting artifact files. Do not copy bulk recon data when a manifest or direct project path is enough.

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

The wrapper also exports the common Hoster recon tool paths before starting
`recon-ry`, including `~/go/bin`, `~/.local/bin`, and `~/bin`. This is required
for non-interactive SSH launches to see Go-installed tools such as Katana.
When Katana is installed, recon-ry's URL/parameter discovery stages can use it
for active crawling and JavaScript parsing, and the resulting JavaScript URLs
flow into `jsfiles.txt`.

The wrapper also stages scope seed files into the remote project before launch:

- `<remote-project>/urls.txt` — exact URLs and exact host/domain entries
- `<remote-project>/wild.txt` — wildcard base domains with leading `*.` removed

For example, `https://app.example.com` stays in `urls.txt`; `*.example.com` becomes `example.com` in `wild.txt`.

The command prints:

- PID
- remote log path
- remote project directory

Do not tail the process for the whole run. Save the PID/log/project path in notes or chat.

## Directory Map

Default active project:

```text
/home/ryushe/bounties/{program}/
```

Legacy/example project locations:

```text
~/Shared/bounty_recon/{program}/
~/projects/bounties/{program}/
```

Recon-ry writes and dedupes its current state into root line files:

```text
{project}/
├── urls.txt          # all known URLs and exact host/domain entries
├── wild.txt          # subdomains and wildcard bases
├── alive.txt         # live HTTP(S) targets after probing
├── params_raw.txt    # raw URLs with parameters from discovery tools
├── params.txt        # normalized/deduped parameterized endpoints
├── jsfiles.txt       # JavaScript URLs for JS/secrets/sink analysis
├── secrets.txt       # secret-scanner output; sensitive until validated
├── dorks.txt         # dork/query leads
├── dirs.txt          # directory/content discovery output when present
├── rate_limit.conf   # project-local rate config
├── history/
│   └── {timestamp}/  # snapshot of root outputs for a specific run
└── screenshots/ or eyewitness/  # visual artifacts when present
```

Root files are the latest deduped view. `history/{timestamp}/` folders are run snapshots. The newest run is usually:

```bash
ls -1t /home/ryushe/bounties/<program>/history | head -1
```

If no `history/` directory exists, use the root files directly.

## Status Pattern

Use status for a short check only:

```bash
python3 agents/recon_ry.py status
```

If needed, inspect the last log lines manually on Hoster, but avoid turning this into a watcher.

## Reading Pattern

When an agent needs recon data:

- start from `alive.txt` for live hosts, browser checks, live-map, and nuclei-style validation
- use `params.txt` for endpoint-heavy testing such as XSS, SQLi, SSRF, redirect, request-shape, and IDOR review
- use `jsfiles.txt` for JavaScript analysis, secrets review, source-map checks, and DOM sink review. `/js` should consume this file and the canonical aggregate, not re-enable crawlers that recon-ry already owns.
- use `urls.txt` for broad URL discovery, route grouping, and API/path clustering
- use `wild.txt` for subdomain or host-level follow-up
- use `history/<newest>/` only when comparing a specific run or checking what changed
- treat `secrets.txt` as sensitive; summarize safely and do not paste raw tokens

## Ingest/Index Pattern

After the run completes, ingest or index the project directory only when Ghost needs a Shared manifest/counts record:

```bash
python3 agents/recon_ry.py ingest <program> \
  --source ryushe@hoster:/home/ryushe/bounties/<program> \
  --target <target-host>
```

The helper can copy known `recon-ry` artifacts into:

```text
~/Shared/web_bounty/{program}/web/recon/recon-ry/{target}/runs/{YYYY-MM-DD}/{run_id}/
```

For large runs, prefer manifest/indexing and direct project references over copying raw bulk data into Shared. Treat the Hoster project directory as the durable recon location unless Ryushe asks for a full archive copy.

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
