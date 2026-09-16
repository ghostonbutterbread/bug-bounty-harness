---
name: recon-ry
description: "Run Ryushe's recon-ry on Hoster and ingest completed outputs into canonical recon artifact directories."
---

# Recon Ry

Use when Ryushe asks to run `recon-ry`, install/check the Hoster recon box, find recon-ry artifacts for a program, or import/index a completed `recon-ry` project into the Ghost bounty pipeline.

This skill is a long-running recon wrapper and directory map. Recon-Ry is the
canonical broad URL/archive collector for `/recon`, including its GAU and
Wayback stages. Start scans and return the PID/log path; do not watch the scan
until completion. When agents need recon data, point them to the recon-ry
project location and artifact map instead of copying bulk output.

## Load Order

1. Read `prompts/recon-ry-playbook.md`.
2. Confirm target scope/rate policy from program notes or `/pullscope` artifacts.
3. Use Hoster via `ryushe@hoster` and `/home/ryushe/.ssh/hoster`.
4. Use `agents/recon_ry.py` for start/status/ingest actions.
5. Treat recon-ry project directories as durable recon storage; do not write high-volume output into the findings ledger.

## Commands

Start a remote run and return immediately:

```bash
bbh agents/recon_ry.py start <program> --url <scoped-domain-or-url> --profile full
```

The start command fails closed if saved scope is missing or the URL is out of scope. It also writes a project-local `rate_limit.conf` before launch. Use `--rate-limit-rps` only after checking the program policy; use `--allow-unscoped` only after explicit Ryushe approval.

Authenticated runs are opt-in:

```bash
bbh agents/recon_ry.py start <program> --url <scoped-domain-or-url> --profile urls --auth blue
```

`--auth <alias-or-color>` resolves through `/account-management` and PwnFox
metadata, stages a locked-down auth seed on Hoster, and only passes auth to
supported active HTTP tools. Manual `--auth-seed-file`, repeatable `--header`,
and `--cookie` are available for approved one-off testing; `--auth-header`
remains a compatibility alias. Raw values must not be pasted into chat or
committed. Dry-run output is redacted.

Before launch, the wrapper stages recon seed files into the remote project:

- `/home/ryushe/bounties/{program}/urls.txt`
- `/home/ryushe/bounties/{program}/wild.txt`

`urls.txt` receives exact URLs and exact host/domain entries. `wild.txt`
receives wildcard base domains with `*.` removed.

Both seed files are **read-only inputs** during a run (enforced since recon-ry
`65189ed`): recon-ry routes tool output to a run-local temp copy and never
writes the project `urls.txt` or `wild.txt`. If either file contains deep
discovered subdomains, that came from outside recon-ry and should be treated as
contamination, not as normal state — `wild.txt` holds roots only.

Check remote status/log names:

```bash
bbh agents/recon_ry.py status
```

Ingest a completed Hoster project:

```bash
bbh agents/recon_ry.py ingest <program> \
  --source ryushe@hoster:/home/ryushe/bounties/<program> \
  --target <target-host>
```

## Recon-Ry Project Location

Active and durable recon-ry project directories use:

```text
/home/ryushe/bounties/{program}/
```

Legacy local examples may also exist at:

```text
~/Shared/bounty_recon/{program}/
~/projects/bounties/{program}/
```

Use the newest `history/` snapshot when the question is about a specific run. Use the root files when the question is about the latest deduped current state.

## Artifact Map

```text
{project}/
├── urls.txt          # all known URLs and exact host/domain seed entries; deduped current state
├── wild.txt          # READ-ONLY roots input: scope wildcard bases, `*.` stripped. Never a tool output.
├── hosts.txt         # host inventory: scope roots + discovered subdomains. Input for URL discovery.
│                     #   (pending: lands with recon-ry `fix/subdomain-enum-all-roots`; before that
│                     #    merges, enum output reaches `urls.txt` via the run-local aggregate)
├── alive.txt         # live HTTP(S) hosts/URLs after probing; primary list for browser/live-map/nuclei follow-up
├── params_raw.txt    # raw parameterized endpoint candidates from discovery tools
├── params.txt        # normalized/deduped URLs with parameters; primary list for XSS, SQLi, SSRF, redirect, IDOR-style endpoint review
├── jsfiles.txt       # JavaScript URLs extracted from parameter/url discovery; primary list for JS/secrets/sink analysis
├── secrets.txt       # secret-scanner findings; treat as sensitive until manually validated and sanitized
├── dorks.txt         # dork/query leads; source-derived candidates, not live facts
├── dirs.txt          # directory/content discovery results when present
├── rate_limit.conf   # per-project rate configuration written by the wrapper
├── history/
│   └── {timestamp}/  # per-run snapshots; newest timestamp is the most recent run
└── screenshots/ or eyewitness/  # visual artifacts when present
```

Recon-ry merges line-based outputs into the root files during runs, so root files are the current deduped view. `history/{timestamp}/` preserves what existed during that run.

## Finding The Latest Data

On Hoster:

```bash
PROJECT=/home/ryushe/bounties/<program>
ls -1t "$PROJECT/history" | head -1
```

For legacy local data:

```bash
PROJECT=~/Shared/bounty_recon/<program>
ls -1t "$PROJECT/history" | head -1
```

If `history/` does not exist, read the project root files directly.

## Output Indexing

Ingest writes:

```text
~/Shared/web_bounty/{program}/web/recon/recon-ry/{target}/runs/{YYYY-MM-DD}/{run_id}/
├── command.txt
├── stdout.txt
├── stderr.txt
├── raw/
├── parsed/
└── manifest.json
```

Use ingest/indexing for manifests, counts, and small parsed artifacts. Do not copy 10GB+ raw recon trees by default when agents can read the recon-ry location directly.

## Role In The Advanced Recon Baseline

For a permitted `/recon --mode full` baseline or a separately selected deep
recon campaign, launch Recon-Ry once as the durable broad collector. It already
owns GAU/Wayback/archive URL collection and its own aggregate promotion path; do
not start overlapping GAU, Wayback, or archive-URL jobs against the same scope
merely because those tools are available.

After Recon-Ry returns, `/recon` may select only evidence-gap-driven companion
lanes: DNS/IP/certificate correlation for approved wildcard hosts, permitted
service/vhost mapping for attributable assets or declared CIDRs, and modest
target-specific search/dork discovery. Those lanes return candidates to the
parent for scope validation and Recon Bus promotion; they do not change
Recon-Ry profile stages or create competing aggregate files.

Recon-Ry establishes the initial durable baseline. Later browser navigation,
task-scoped agent-proxy observations, new JavaScript hashes, request shapes, and
route/parameter discoveries enrich their owning stores incrementally. Run a
Recon-Ry delta only for a material deployment/scope change, a concrete coverage
gap, or freshness uncertainty—not for every later application discovery.

## File Contracts

Keep these distinct. Collapsing them is what silently zeroed out subdomain
enumeration on epicgames (a deep leaf sorted to line 1 of `wild.txt`, and the
enum stage used `head -n 1` as its only domain).

| File | Direction | Holds |
|---|---|---|
| `wild.txt` | read-only input | scope wildcard base domains, `*.` stripped. Roots only. |
| `hosts.txt` | tool output + input | scope roots plus every discovered subdomain. What URL discovery crawls. |
| `alive.txt` | tool output | hosts/URLs that answered the most recent probe. Never write unprobed discoveries here. |

Do not add a tool whose `outputs:` is `wild.txt`, and do not point a tool's
`required_files:` at `wild.txt` when it wants the full host list.

## Rules

- Treat `recon-ry` outputs as recon artifacts, not confirmed vulnerabilities.
- Promote to the findings ledger only after a separate high-confidence validation step.
- Keep Hoster logs and bulk raw artifacts on Hoster unless Ryushe explicitly asks to archive them elsewhere.
- Prefer root project files for current deduped state; prefer `history/{timestamp}/` for run-specific snapshots.
- Stop before running high-volume recon on a target without explicit scope/rate approval.
- Never bypass the saved-scope check unless Ryushe explicitly approves the target and rate limit.
- Do not treat an IP, ASN, co-hosted domain, historical DNS record, or public
  search result as scope expansion. Preserve unattributed records as labelled
  evidence until current attribution and saved-scope validation permit follow-up.
- Documentation and public code are retrieved later only for a concrete
  endpoint, technology, integration, or behavior-comparison question; they are
  not default broad-collection lanes.
- Auth is never default. It is applied only to active HTTP-capable tools such as
  Katana, httpx/http_fingerprinting, param_recon's Katana path, ffuf, and nuclei.
  Passive recon, DNS/IP enrichment, naabu, nmap/service enrichment, dorking, and
  local filesystem secret scanning remain unauthenticated.
