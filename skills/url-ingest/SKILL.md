# url-ingest — URL Ingestor + Review Tracker

## What it is
SQLite-backed URL index and per-lane review tracker. Keeps a durable record of every URL discovered in recon and what kind of analysis (if any) has been done on it per vulnerability lane.

## Location
- **Engine:** `agents/url_ingest.py`
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

/url-ingest status <program> [--lane <lane>] [--url <url>]
   Show review status for URLs. Use --url for exact lookup, --lane to filter by vuln lane.

/url-ingest mark <program> --url <url> --lane <lane> --status <status>
              [--skill <skill>] [--test-family <family>] [--technique <technique>]
              [--notes <notes>] [--evidence <path>] [--agent-id <id>] [--run-id <id>]
   Append a test-run event and update the latest summary for a URL in a given lane.

   Valid statuses:
     discovered          — seen in recon, not yet reviewed
     surface_reviewed    — skimmed/classified, no deep testing
     deep_reviewed       — agent or human tested with meaningful effort
     validated_signal    — interesting enough to route to a vuln lane
     dismissed           — intentionally deprioritized with reason

/url-ingest search <program> [--route-hash <hash>] [--param-hash <hash>]
                             [--host <host>] [--lane <lane>] [--limit <n>]
   Search URLs by route hash, param-shape hash, or host.

/url-ingest next <program> --lane <lane> [--skill <skill>] [--test-family <family>]
                            [--param-preset xss|ssrf|lfi|opaque-state] [--limit <n>]
   List URLs not yet tested for that lane/skill/family combination.
   Use `--param-preset` for parameter-aware queues instead of generic first-seen ordering.

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

Before testing a URL in a lane, call `/url-ingest status` to check if it's already `deep_reviewed` or `dismissed` for that lane.

Before running a specific technique across URLs, call `/url-ingest next` with `--skill` and `--test-family` so agents do not repeat the same work.

After testing, call `/url-ingest mark` with the skill, test family, and technique. This writes an append-only test event, then updates the compact per-lane summary.

Examples:

```bash
python3 agents/url_ingest.py next canva --lane recon --skill user-agent-fuzz --test-family header-behavior --limit 25

python3 agents/url_ingest.py next canva --lane xss --skill xss --test-family reflected-probe --param-preset xss --limit 25
python3 agents/url_ingest.py next canva --lane ssrf --skill ssrf --test-family url-fetcher-probe --param-preset ssrf --limit 25
python3 agents/url_ingest.py next canva --lane lfi --skill lfi --test-family path-traversal-probe --param-preset lfi --limit 25
python3 agents/url_ingest.py next canva --lane recon --skill param-fuzz --test-family opaque-state-map --param-preset opaque-state --limit 25

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
