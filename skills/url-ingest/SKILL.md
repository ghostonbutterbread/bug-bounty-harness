---
name: url-ingest
description: Use when importing, indexing, filtering, queueing, checking, or marking recon URLs in the SQLite-backed per-lane URL review tracker.
---
# url-ingest — URL Ingestor + Review Tracker

## What it is
SQLite-backed URL index, parameter map, and per-lane review tracker. Keeps a durable record of every URL discovered in recon, every observed query parameter, and what kind of analysis has been done at URL, route, or parameter level.

Unified recon-store rule: recon agents and one-off recon tools must preserve raw artifacts first, then ingest URL/host-shaped parsed artifacts into this database. Do not leave amass/recon-ry/proxy/recon output as an isolated text file when it is meant to inform later agents.

`/url-ingest` is not the notes layer. Use it for bulk URL intake, dedupe,
parameter inventory, queue selection, and per-lane reviewed/tested state.

Use `/map-store` for technical observations learned while reviewing a URL. Use
`/bounty-notes` for timeline, hypotheses, handoffs, FAQs, and human-readable
hunt narrative.

## Location
- **Engine:** `agents/url_ingest.py`
- **Recon artifact recorder:** `agents/recon_store.py`
- **Playbook:** `prompts/url-ingest-playbook.md`
- **DB storage:** `~/Shared/web_bounty/<program>/web/recon/url_index/url_index.sqlite`

## Usage

```
/url-ingest init <program>
   Create the DB schema for a program.

/url-ingest ingest <program> --source <file> [--run-id <id>] [--scope-filter auto] [--no-repull-scope]
   Import URLs from a recon artifact file (e.g. alive.txt, params_raw.txt) into the DB.
   Deduplicates by canonical URL hash.
   With `--scope-filter auto`, writes scoped and rejected temp files first, then ingests only scoped URLs when scope exists.
   With `--scope-filter auto`, missing saved scope automatically triggers the existing `agents/scope_puller.py` across HackerOne, Bugcrowd, and Intigriti before falling back.
   Use `--no-repull-scope` only for explicit passive/import-only work where scope pulling is intentionally skipped.

/url-ingest aggregate <program> [--input <dir>] [--run-id <id>] [--scope-filter auto] [--no-ingest]
   Build central program-level recon files under:
   `~/Shared/web_bounty/<program>/web/recon/aggregated/`

   This scans known recon roots by default, including recon-ry output, and aggregates:
   `wild.txt`, `urls.txt`, `alive.txt`, `params_raw.txt`, `params.txt`, `jsfiles.txt`, and `dirs.txt`.
   `live.txt` is accepted as an alias for `alive.txt`.

   It uses `anew` for incremental append/delta tracking when available, and `uro` for URL/parameter normalization when available. The helper checks PATH first, then common recon-ry locations such as `~/go/bin/anew`, `~/.local/bin/uro`, and `~/tools/recon-ry/venvs/uro/bin/uro`.
   Each run writes:
   - `runs/<run-id>/incoming/*.txt`
   - `runs/<run-id>/normalized/*.txt`
   - `runs/<run-id>/delta/*.txt`
   - `runs/<run-id>/manifest.json`
   - root-level current aggregate files such as `params.txt`, `urls.txt`, and `jsfiles.txt`

   Use this before handing agents a broad program URL set. For example, "Canva params" should resolve to:
   `~/Shared/web_bounty/canva/web/recon/aggregated/params.txt`

   With default settings, the aggregate command also imports aggregate URL-shaped files into SQLite so `/url-ingest next`, `/url-ingest mark`, and per-agent review state keep working.
   `--input` is repeatable; use it for any recon-ry, dorking, crawler, proxy, or one-off tool output directory that should feed the aggregate store. `--source-root` remains a compatibility alias.

## Recon Aggregate Policy
All recon-producing agents must route URL-like output into the program aggregate store before handing URLs to testing agents.

Canonical location:
`~/Shared/web_bounty/<program>/web/recon/aggregated/`

Canonical files:
- `urls.txt` — all discovered HTTP(S) URLs and URL-like exact targets
- `alive.txt` — URLs/hosts after HTTP probing; `live.txt` inputs are normalized here
- `params_raw.txt` — raw parameterized URLs before final normalization
- `params.txt` — normalized parameterized URLs for XSS/SQLi/SSRF/open-redirect/IDOR review
- `jsfiles.txt` — JavaScript URLs for JS/secrets/sink analysis
- `wild.txt` — host/subdomain-shaped discoveries
- `dirs.txt` — directory/content-discovery leads

Required agent flow:
1. Preserve raw tool output in the tool/run directory first.
2. Append into aggregate storage with:
   `python3 agents/url_ingest.py aggregate <program> --input <tool-output-dir> --run-id <run-id>`
3. Let aggregate use `anew` for incremental text deltas and `uro` for URL/parameter normalization.
4. Let aggregate import URL-shaped output into SQLite unless explicitly using `--no-ingest` for a dry text-only test.
5. Before testing, query SQLite with `brief`, `next`, `status`, or `history`.
6. After testing, record coverage with `mark --agent-id <agent> --skill <skill> --test-family <family>`.

Do not hand agents a standalone dork/crawler/proxy URL file as the long-term source of truth. Standalone files are raw evidence; the aggregate files and SQLite index are the shared working state.

Duplicate handling:
- `anew` prevents exact duplicate lines from accumulating in aggregate text files.
- `uro` reduces URL clutter before appending.
- SQLite canonicalization is still the authoritative dedupe/review layer; expect some semantic/canonical duplicates between text-file line counts and DB URL counts over time.

For one-off recon files, use:

```
python3 agents/recon_store.py <program> --tool <tool-name> --target <domain-or-url> --source <artifact-file>
```

This keeps the raw artifact and imports URL/host-shaped records into SQLite.

/url-ingest status <program> [--lane <lane>] [--url <url>]
   Show review status for URLs. Use --url for exact lookup, --lane to filter by vuln lane.

/url-ingest mark <program> --url <url> --lane <lane> --status <status>
              [--skill <skill>] [--test-family <family>] [--technique <technique>]
              [--param <name>] [--param-location <query|body|header|path|graphql>]
              [--notes <notes>] [--evidence <path>] [--agent-id <id>] [--run-id <id>]
   Append a test-run event and update the latest summary for a URL in a given lane.
   Use `--param` when the review is scoped to one parameter rather than the whole URL.

   Valid statuses:
     discovered          — seen in recon, not yet reviewed
     surface_reviewed    — skimmed/classified, no deep testing
     deep_reviewed       — agent or human tested with meaningful effort
     validated_signal    — interesting enough to route to a vuln lane
     dismissed           — intentionally deprioritized with reason

/url-ingest search <program> [--route-hash <hash>] [--param-hash <hash>]
                             [--host <host>] [--lane <lane>] [--limit <n>]
   Search URLs by route hash, param-shape hash, or host.

/url-ingest brief <program> [--limit <n>]
   Show compact agent-safe totals, top hosts, common parameter keys, and recent imports.

/url-ingest next <program> --lane <lane> [--skill <skill>] [--test-family <family>]
                            [--param <name>] [--param-preset xss|ssrf|lfi|opaque-state] [--limit <n>]
   List URLs not yet tested for that lane/skill/family combination.
   Use `--param` for exact parameter-level queues and `--param-preset` for broader dynamic parameter-aware queues.

/url-ingest params <program> [--lane <lane>] [--param <name>] [--host <host>] [--untested]
   Show the parameter map derived from ingested URLs: parameter name, location,
   value shape, lane hints, count of URLs, example URL, and route preview.
   This is the structured view of `aggregated/params.txt`, not a replacement for it.

/url-ingest history <program> --url <url>
   Show append-only test events for one URL.

/url-ingest stats <program>
   Show DB statistics: total URLs, status breakdown, test-family breakdown, last import.

## Per-lane status semantics
A URL can have a different status per vulnerability lane:

| Status | Meaning |
|--------|---------|
| `discovered` | Seen in recon, not yet reviewed for this lane |
| `surface_reviewed` | Skimmed for this lane, no deep testing |
| `deep_reviewed` | Tested with meaningful effort for this lane |
| `validated_signal` | Interesting for this lane — route to XSS/SSRF/etc. |
| `dismissed` | Intentionally skipped, with reason in notes |

## Agent protocol
For URLs that may feed live testing, prefer scoped ingestion:

```bash
python3 agents/url_ingest.py ingest <program> \
  --source /path/to/urls.txt \
  --run-id <run-id> \
  --scope-filter auto
```

Behavior:
- saved scope exists: accepted/rejected temp files are written under `/tmp`, and only accepted URLs are ingested
- no saved scope: `--scope-filter auto` tries the existing pullscope engine against HackerOne, Bugcrowd, and Intigriti before fallback
- no scope after repull: passive parsing may continue, but the import is labeled `scope_mode=no_scope_after_pull`; agents must not treat this as live-test approval

Before testing a URL in a lane, call `/url-ingest status` to check if it's already `deep_reviewed` or `dismissed` for that lane. If testing a specific parameter, include `--param <name>`.

Before running a specific technique across URLs, call `/url-ingest next` with `--skill` and `--test-family` so agents do not repeat the same work.

After testing, call `/url-ingest mark` with the skill, test family, technique, and `--param` when relevant. This writes an append-only test event, then updates the compact per-lane summary.

Examples:

```bash
python3 agents/url_ingest.py next canva --lane recon --skill user-agent-fuzz --test-family header-behavior --limit 25

python3 agents/url_ingest.py next canva --lane xss --skill xss --test-family reflected-probe --param-preset xss --limit 25
python3 agents/url_ingest.py next canva --lane xss --skill gf --test-family dynamic-filter --param q --limit 25
python3 agents/url_ingest.py next canva --lane ssrf --skill ssrf --test-family url-fetcher-probe --param-preset ssrf --limit 25
python3 agents/url_ingest.py next canva --lane lfi --skill lfi --test-family path-traversal-probe --param-preset lfi --limit 25
python3 agents/url_ingest.py next canva --lane recon --skill param-fuzz --test-family opaque-state-map --param-preset opaque-state --limit 25

python3 agents/url_ingest.py params canva --lane ssrf --untested --limit 25

python3 agents/url_ingest.py mark canva \
  --url "https://www.canva.com/help/" \
  --lane recon \
  --status surface_reviewed \
  --skill user-agent-fuzz \
  --test-family header-behavior \
  --technique desktop-vs-mobile-agent \
  --request-variant "changed User-Agent only" \
  --response-summary "status and length unchanged" \
  --notes "No behavior delta."

python3 agents/url_ingest.py mark canva \
  --url "https://www.canva.com/search?q=logo" \
  --lane xss \
  --status surface_reviewed \
  --skill gf \
  --test-family dynamic-filter \
  --param q \
  --notes "GF xss candidate reviewed; no reflection observed."
```

## Ingest from Hoster
To ingest from the Hoster recon-ry output:

```bash
# Copy file locally, then ingest
scp hoster:/home/ryushe/bounties/<program>/alive.txt /tmp/alive_<program>.txt
python3 agents/url_ingest.py ingest <program> --source /tmp/alive_<program>.txt --run-id <run-id>

# Or pipe over SSH
ssh hoster 'cat /home/ryushe/bounties/<program>/alive.txt' | \
    python3 agents/url_ingest.py ingest <program>
```

## Supported lanes
recon, xss, sqli, ssrf, idor, access-control, ssti, open-redirect, xxe, race, csrf
(Custom lanes are accepted; standard lanes are checked for typo warnings.)
