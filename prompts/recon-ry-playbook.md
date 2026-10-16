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

This preflight applies to **every** active profile, including `snap` and `full`: review
the entire saved scope for a wildcard grant alongside any separately
origin/path-limited exact URL. The wrapper can accept `snap` or `full`, stage both, and
reduce the exact URL to a host. Do not launch that mixed set unless program
authorization explicitly covers the host-wide activity **or** each enabled
active stage is verified to avoid requests outside the restricted grant. A
scoped seed URL and post-run filtering do not enforce this boundary. When
unresolved, defer active broad collection; keep narrow-source/passive review
within its own rules.

Start via the local wrapper so Hoster owns the long-running process:

```bash
bbh agents/recon_ry.py start <program> --url <scoped-domain-or-url>
```

This launches Recon-Ry's `snap` profile by default. It omits port enrichment,
directory brute force, and screenshots, but still performs active wildcard
recon; request `--profile full` explicitly for its additional stages when
authorized. The wrapper checks the seed against saved scope before starting;
this is not request-level confinement for all stages. The derived scope file reduces root
URLs to hosts, so it cannot enforce a scheme, port, or allowed-path grant:

- if no saved scope exists for the program, it stops
- if the seed URL is not in scope, it stops
- `--allow-unscoped` is only for explicit Ryushe-approved runs with no saved scope; it never disables an existing saved host filter or exclusion

### Exact-host grants versus origin/path-limited grants

For a program with exact targets (with or without a wildcard elsewhere),
classify each saved grant first. A URL limited to one scheme/port or an allowed
path is **not** a host-wide grant. Do not run active `exact-urls` stages for
such a target until request-level destinations are constrained and verified or
the program separately approves wider host activity. Path-scoped
repository/package URLs stay source review only; do not treat them as whole-host
seeds. Passive/source review may continue within its own authorization.

For an approved host-wide target, verify each enabled stage's request behavior
against saved scope, then launch **one** host with its own project:

```bash
bbh agents/recon_ry.py start <program> \
  --url <approved-host-url> \
  --profile exact-urls \
  --remote-project /home/ryushe/bounties/<program>/exact/<host-key>
```

`exact-urls` keeps the standard project and artifact schema but omits subdomain
enumeration, IP/port enrichment, and any promotion of sibling hosts. It runs
exact-host web stages: crawl/archive URL discovery, alive checks, HTTP
fingerprinting, parameter/JS discovery, directory discovery, secret scanning,
URL ranking, and EyeWitness. Its URL-bearing outputs are filtered back to the
seed **host**; this does not prove request-level confinement to the authorized
origin/path, or undo any prior out-of-scope request.

For multiple approved hosts, use a distinct `--remote-project` per host. `start`
defaults to the **same** program project and backgrounds each job, so do not
launch the next host until the prior PID has completed and its log/project
receipt is inspected. Record the eligible count and deferred assets; one-host
smoke is not scope-wide coverage. Do not substitute the detached multi-host
queue as an automatic aggregate-rate or containment guarantee.

The wrapper writes `<remote-project>/rate_limit.conf` before launch. Default is
`--rate-limit-rps 2` per project, **not** an aggregate concurrent cap;
`--timeout 0` disables the per-tool timeout. Set tighter limits when program
policy requires them, and increase request rate only when allowed.

Authenticated recon is opt-in and should use the existing account resolver:

```bash
bbh agents/recon_ry.py start <program> \
  --url <host-wide-approved-url> \
  --profile exact-urls \
  --auth blue \
  --remote-project /home/ryushe/bounties/<program>/exact/<host-key>
```

`--auth <alias-or-color>` resolves through
`skills/account-management/scripts/auth_resolver.py`, refreshes only when the
account inventory permits it, stages a `0600` auth seed under the remote
project's `.auth/` directory, and sets `RECON_RY_AUTH_SEED` for recon-ry.
Manual `--auth-seed-file`, repeatable `--header`, and `--cookie` are for approved
single-host testing only. Credentialed `start` requires `--profile exact-urls`;
credentialed `queue` is rejected so one auth seed cannot cross queued hosts.
`--auth-header` remains a compatibility alias for `--header`. Dry-run output
must show only redacted metadata such as cookie count and header names. The
wrapper selects Recon-Ry's `exact-urls-header` profile when a seed is present;
it excludes top-level tools without verified header forwarding (including
EyeWitness), but does not prove request-level host confinement for every tool.

Auth-capable recon-ry stages:

- `katana`
- `httpx`
- `http_fingerprinting`
- `param_recon`'s internal Katana path
- `ffuf`
- `nuclei`

Auth does not apply to passive sources or network/service discovery:

- subfinder, crt.sh, assetfinder, passive amass, waybackurls, gau, waymore,
  uro, js file normalization, dorking, and local secret scanning
- DNS/IP enrichment, naabu, and nmap/service enrichment

For credentialed starts the wrapper narrows staged seeds to the approved
`--url` target, leaves `wild.txt` empty, and does not run wildcard-dependent
profiles. Repeatable `--header` values—including Authorization and program
attribution headers—are treated as credentials regardless of their names.
Unauthenticated `snap`, `full`, `subs`, and `fast` runs enumerate eligible staged
wildcard roots; if every saved root was excluded, the wrapper refuses to
fall back to subdomain enumeration from an exact URL.

The wrapper also exports the common Hoster recon tool paths before starting
`recon-ry`, including `~/go/bin`, `~/.local/bin`, and `~/bin`. This is required
for non-interactive SSH launches to see Go-installed tools such as Katana.
When Katana is installed, recon-ry's URL/parameter discovery stages can use it
for active crawling and JavaScript parsing, and the resulting JavaScript URLs
flow into `jsfiles.txt`.

The wrapper also stages scope seed files into the remote project before launch:

- `<remote-project>/urls.txt` — exact URLs and exact host/domain entries
- `<remote-project>/wild.txt` — wildcard base domains with leading `*.` removed.
  Roots only, and read-only for the duration of a run: recon-ry writes tool
  output to a run-local copy, never to the project seed files.

For example, `https://app.example.com` stays in `urls.txt`; `*.example.com` becomes `example.com` in `wild.txt`.

The command prints:

- PID
- remote log path
- remote project directory

Do not tail the process for the whole run. Save the PID/log/project path in notes or chat.

## Directory Map

Default active project (wildcard/broad); distinct exact-host projects live under
`/home/ryushe/bounties/{program}/exact/{host-key}/` when selected via
`--remote-project`:

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
├── wild.txt          # READ-ONLY roots input: wildcard bases, `*.` stripped
├── hosts.txt         # host inventory: roots + discovered subdomains (pending
│                     #   recon-ry fix/subdomain-enum-all-roots)
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

Each selected project's root files are its latest deduped view;
`history/{timestamp}/` beneath that **same project** contains its run
snapshots. Select the completed `start` receipt's `project=` path first: the
program root for a broad run, or the separate `exact/` project for that host.
Do not read program-root files/history to represent an exact-host run. For
example, to inspect a completed exact-host project:

```bash
PROJECT=/home/ryushe/bounties/<program>/exact/<host-key>
ls -1t "$PROJECT/history" | head -1
```

For a broad run, set `PROJECT=/home/ryushe/bounties/<program>` instead. If
that selected project's `history/` is absent, read **its** root files directly.

Large EyeWitness stores should live on the mounted bounty volume, not inside
`/home/ryushe/bounties`. Hoster recon-ry supports
`tools.eyewitness.large_project_dir`; when it is set to `/mnt/bounty` and
`tools.eyewitness.store_dir` is left at the legacy default, the resolved store
is:

```text
/mnt/bounty/{program}/web/recon/eyewitness
```

Use that resolved EyeWitness store for screenshot/source/report lookups. The
project-local `/home/ryushe/bounties/{program}/eyewitness` path may be only a
compatibility symlink.

## Status Pattern

Use status for a short check only:

```bash
bbh agents/recon_ry.py status
```

If needed, inspect the last log lines manually on Hoster, but avoid turning this into a watcher.

## Reading Pattern

When an agent needs recon data, resolve the completed run's `project=` path
before following these file names; for exact-host runs use each host's distinct
project, not the program root:

- start from `alive.txt` for live hosts, browser checks, live-map, and nuclei-style validation
- use `params.txt` for endpoint-heavy testing such as XSS, SQLi, SSRF, redirect, request-shape, and IDOR review
- use `jsfiles.txt` for JavaScript analysis, secrets review, source-map checks, and DOM sink review. `/js` should consume this file and the canonical aggregate, not re-enable crawlers that recon-ry already owns.
- use `urls.txt` for broad URL discovery, route grouping, and API/path clustering
- use `wild.txt` only to read the program's wildcard roots. For subdomain or
  host-level follow-up use the host inventory (`hosts.txt` once
  fix/subdomain-enum-all-roots lands; until then the aggregate `hosts.txt`
  maintained by Recon Bus). Never treat `wild.txt` as a discovered-host list,
  and never write to it.
- if an authenticated run was used, read `.auth/auth_metadata.json` for safe
  account/color/session labels. Do not read or copy the raw `.auth/recon-ry-auth.json`
  seed into prompts, reports, or chat.
- use `history/<newest>/` only when comparing a specific run or checking what changed
- treat `secrets.txt` as sensitive; summarize safely and do not paste raw tokens

## Ingest/Index Pattern

After a run completes, ingest the **completed project's own directory** only
when Ghost needs a Shared manifest/counts record. For a broad program-root run:

```bash
bbh agents/recon_ry.py ingest <program> \
  --source ryushe@hoster:/home/ryushe/bounties/<program> \
  --target <program-root-target>
```

For exact-host runs, use the `project=` path recorded by each completed
`start`, not the program root. Repeat once per completed host, with a distinct
`--target` matching that host; inspect the run receipt before the next host's
start. The wrapper copies artifacts from the specified directory only—it does
not descend into sibling `exact/` projects:

```bash
bbh agents/recon_ry.py ingest <program> \
  --source ryushe@hoster:/home/ryushe/bounties/<program>/exact/<host-key> \
  --target <approved-host>
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
