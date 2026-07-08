# Bounty Tools Playbook

Use this playbook when an agent runs external tooling that produces reusable
bug bounty data. The goal is repeatability: future agents should know what ran,
where the raw output lives, which normalized data is current, and what rate
limits or stop conditions governed the run.

## Directory Contract

For web bounty work, use:

```text
~/Shared/web_bounty/<program>/web/recon/tools/<tool>/
├── global/
│   ├── hosts.txt
│   ├── urls.txt
│   ├── params_raw.txt
│   ├── params.txt
│   ├── jsfiles.txt
│   └── manifest.json
└── runs/
    └── YYYY-MM-DD/
        └── <run-id>/
            ├── manifest.json
            ├── command.txt
            ├── raw/
            ├── parsed/
            ├── normalized/
            ├── summary.md
            └── handoff.json
```

`runs/YYYY-MM-DD/<run-id>/` is the immutable run record. `global/` is the
tool-level cumulative view. The cross-tool current view remains:

```text
~/Shared/web_bounty/<program>/web/recon/aggregated/
```

Use `tool-run` for spawned tools that emit reusable URL-like recon data. It
creates the run capsule, captures stdout/stderr, writes the manifest, and calls
recon-bus promotion when the command exits successfully. Use recon-bus
`promote-run` or `watch-runs` for completed run directories that were produced
outside the wrapper.

## Tool-Run Wrapper

When an agent runs a recon/mapping/fuzzing tool that can produce URLs, alive
URLs, params, JS URLs, hosts, or dirs, prefer:

```bash
tool-run <program> -- <command>
```

Example:

```bash
tool-run flourish -- katana -u https://target.example -o normalized/urls.txt
```

The wrapper infers the tool name from the first command token. Use
`--tool <name>` only when the inferred name would be misleading.

Inside the wrapper's working directory, tools should write known outputs under
`normalized/`:

- `urls.txt`
- `alive.txt`
- `params_raw.txt`
- `jsfiles.txt`
- `hosts.txt`
- `dirs.txt`

For params, keep the mental model simple: append/promote into `params_raw.txt`;
recon bus regenerates `params.txt` with URO. Do not hand-edit aggregate
`params.txt` as a canonical input.

## Run ID

Use stable run IDs:

```text
<tool>-<program>-YYYYMMDDTHHMMSSZ
```

Examples:

```text
ffuf-canva-20260618T003000Z
dalfox-superdrug-20260618T003000Z
nmap-target-20260618T003000Z
```

## Manifest

Every run should write `manifest.json`:

```json
{
  "schema": "bbh.tool_run.v1",
  "program": "example",
  "family": "web_bounty",
  "lane": "web",
  "tool": "ffuf",
  "tool_version": "unknown",
  "run_id": "ffuf-example-20260618T003000Z",
  "target": "https://www.example.com/FUZZ",
  "command_file": "command.txt",
  "raw_dir": "raw",
  "parsed_dir": "parsed",
  "normalized_dir": "normalized",
  "rate": {
    "rps": 15,
    "concurrency": 1,
    "source": "program limit silent; capped by bounty-tools"
  },
  "scheduler": {
    "lock_key": "www.example.com",
    "parallelism": "single live noisy tool per host/app area"
  },
  "scope": {"source": "program notes or pullscope", "status": "checked"},
  "auth_state": "anonymous",
  "status": "completed",
  "started_at": "2026-06-18T00:30:00Z",
  "finished_at": "2026-06-18T00:45:00Z",
  "counts": {"raw_lines": 0, "normalized_urls": 0, "interesting": 0},
  "stop_reason": "completed wordlist"
}
```

`command.txt` must be sanitized. Replace secrets with references:

```text
Cookie: <credential-ref:canva-owned-user-a-cookie>
Authorization: Bearer <credential-ref:canva-owned-user-a-token>
```

## Rate, Scope, And Scheduling Defaults

Use explicit rate and concurrency. Never rely on tool defaults when the tool can
send many requests.

Program policy wins. If the program publishes a lower rate, use it. If the
program is silent and the target is stable, `15 rps` is the maximum live HTTP
budget per host or app area.

- effective cap: `min(program_rate_limit, 15 rps)`
- one noisy live tool at a time per host or app area by default
- parallel runs are allowed across clearly separate root domains or independent
  app areas when each run has its own rate budget and output root
- passive/offline tools may run in parallel because they do not touch the target
- authenticated, fragile, checkout, account, or admin-like flows should start at
  `1-3 rps` even if the global cap is higher
- concurrency `1-2` by default unless the tool needs a higher value to maintain
  the selected rps cleanly
- crawler depth `1-2` until the app map proves the route cluster is safe

For `ffuf`, prefer:

```bash
ffuf -u "https://target.example/FUZZ" \
  -w /path/to/wordlist.txt \
  -rate 15 \
  -json \
  -o "<run-root>/raw/ffuf.json"
```

For `nmap`, scope hosts tightly and avoid aggressive timing unless approved:

```bash
nmap -sV -T2 -oA "<run-root>/raw/nmap" <host-or-cidr>
```

For `dalfox`, preserve JSONL:

```bash
dalfox scan urls.txt --format jsonl --output "<run-root>/raw/dalfox.jsonl"
```

For `dursgo`, preserve JSON:

```bash
dursgo -u https://target.example -s none -c 3 -d 2 -output-json "<run-root>/raw/dursgo-map.json"
```

## Run Gating

Before starting live target traffic, create or check a lock for the host or app
area:

```text
~/Shared/<family>/<program>/<lane>/recon/tools/.locks/<host-or-area>.lock
```

The lock should name the active `run_id`, tool, target, started timestamp, rps,
and manifest path. If another noisy live tool is already running for the same
host or app area, queue the new run and start it after the active manifest
reaches `completed`, `stopped`, or `failed`.

Examples:

- allowed in parallel: `ffuf` on `api.example.com` and `dalfox` on
  `shop.other-root.example` when both are in scope and each has a rate budget
- normally queued: `ffuf`, `dalfox`, and `dursgo` all hitting
  `www.example.com` route clusters
- always allowed: parsing saved `gau` output while a live `ffuf` run is active

Do not delete a lock blindly. Check whether the referenced process is still
running and whether the manifest has a terminal status.

## Stop Conditions

Do not stop on one isolated noisy response. First reduce rps, narrow the target
set, improve filters, or switch to a more appropriate mode when that is safe.
Stop and summarize when any of these persist enough that the run is producing
messy requests instead of useful signal:

- repeated `429`, WAF, CAPTCHA, bot challenge, temporary ban, or account lock
- repeated account friction such as forced logout, MFA prompts, lockout warnings,
  verification loops, or anti-automation interstitials
- elevated `5xx` or unstable responses that make filtering unreliable
- unexpected state-changing requests
- destructive behavior or emails/messages being sent
- non-owned resource IDs or cross-tenant data
- out-of-scope hosts, paths, APIs, or subsidiaries

If the interesting signal is WAF/rate-limit behavior, route to `/waf` or
`/error-triage` instead of increasing volume.

When a run stops because of blocking or account friction, the summary should
include:

- approximate request count and response pattern
- rate/concurrency at the time of blocking
- whether cookies, auth context, headed browser mode, proxy context, or a smaller
  route cluster is the likely next attempt
- why the agent stopped instead of continuing

## Normalization

Write extracted reusable data into `normalized/`:

- `hosts.txt`
- `urls.txt`
- `alive.txt`
- `params_raw.txt`
- `jsfiles.txt`
- `dirs.txt`

`params.txt` is a derived URO-cleaned view. If a legacy tool emits only
`params.txt`, recon-bus can use it as fallback input, but normal tools should
write `params_raw.txt`.

`hosts.txt`, `wild.txt`, and `dirs.txt` are aggregate inventory for subdomain
enumeration and content-discovery/fuzzing workflows. They are not automatically
inserted into the URL review index. Promote confirmed URL/alive output
separately when those leads become concrete HTTP targets.

For direct discoveries made by an agent during exploration, append through the
recon bus instead of hand-editing aggregate files:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 scripts/recon_bus.py append <program> --kind url --input new_urls.txt
python3 scripts/recon_bus.py append <program> --kind url --input new_urls.txt --liveness probe
python3 scripts/recon_bus.py append <program> --kind alive --input httpx_alive.txt
python3 scripts/recon_bus.py append <program> --kind param --input params_raw.txt
python3 scripts/recon_bus.py append <program> --kind js --input jsfiles.txt
```

Use `--liveness probe` only when live probing is approved for the target. It
appends candidates to `aggregated/urls.txt`, runs `httpx` only against the new
delta, and appends confirmed output to `aggregated/alive.txt`.

For completed run directories that were not launched through `tool-run`, ingest:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 scripts/recon_bus.py promote-run <program> --run-root "<run-root>"
```

For long-running jobs or delayed workers, use the watcher as a one-shot cron or
heartbeat-safe pass:

```bash
cd "${HARNESS_ROOT:-$HOME/projects/bug_bounty_harness}"
python3 scripts/recon_bus.py watch-runs <program> --root "$HOME/Shared/web_bounty/<program>/web/recon/tools"
```

If output is not URL-like, keep it in `parsed/` and summarize the useful leads in
`summary.md` or `handoff.json`.

## Global Files

Tool-level `global/` files are cumulative per tool. Use append/dedupe helpers
such as `anew` where available. Do not treat `global/` as proof that a target
was tested. Recon-bus aggregates are the lightweight cross-tool inventory;
`url_ingest` is the review/queue/state system for large URL lists and for
answering whether a URL or parameter has already been inspected for a given
lane, skill, or test family.

Minimum global files by tool type:

- URL collectors: `global/urls.txt`, `global/params_raw.txt`, `global/jsfiles.txt`
- content fuzzers: `global/dirs.txt`, `global/urls.txt`
- host scanners: `global/hosts.txt` for tool-local host output
- XSS mappers: `global/params_raw.txt`, `global/xss_candidates.jsonl`

Service and port facts are cross-tool, not nmap-only. Preserve each producer's
raw output under its run capsule, then normalize rows into:

```text
~/Shared/<family>/<program>/<lane>/recon/services/
├── ports.jsonl
├── ports.txt
├── services.jsonl
└── hosts/<host>.jsonl
```

Use `naabu` as a fast port producer, `nmap` as a bounded service/version
enrichment producer, and `httpx` as HTTP fingerprint evidence. Do not bury this
inventory in `cron/_meta`; `_meta` should only keep scheduler decisions,
locks, run indexes, and routing hints.

## Agent Handoff

Use `handoff.json` for specialist lanes. Keep packets small and evidence-backed:

```json
{
  "tool": "dalfox",
  "run_id": "dalfox-example-20260618T003000Z",
  "program": "example",
  "url": "https://www.example.com/search?q=test",
  "method": "GET",
  "params": ["q"],
  "signal": "reflected parameter with angle brackets preserved",
  "auth_state": "anonymous",
  "output_path": "raw/dalfox.jsonl",
  "next_skill": "reflected-xss",
  "status": "Potential"
}
```

The receiving lane must dynamically verify the lead. Tool output alone should
not become a finding.

## Completion Checklist

- `manifest.json` written.
- `command.txt` sanitized.
- Raw output preserved.
- Parsed/normalized output written when useful.
- URL-like output promoted through `tool-run`, `promote-run`, or `append`.
- Large review sets queued or status-tracked through `url_ingest` when agents
  need scoped batches or need to check whether a URL/param has already been
  looked at for the current lane, skill, or test family.
- Tool `global/` view updated when useful.
- `summary.md` includes stop reason, rate/concurrency, and next handoff.
- Findings, if any, are routed to the owning specialist skill.
