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

/url-ingest ingest <program> --source <file> [--run-id <id>]
   Import URLs from a recon artifact file (e.g. alive.txt, params_raw.txt) into the DB.
   Deduplicates by canonical URL hash.

/url-ingest status <program> [--lane <lane>] [--url <url>]
   Show review status for URLs. Use --url for exact lookup, --lane to filter by vuln lane.

/url-ingest mark <program> --url <url> --lane <lane> --status <status>
              [--notes <notes>] [--evidence <path>] [--agent-id <id>] [--run-id <id>]
   Record an observation (analysis depth update) for a URL in a given lane.

   Valid statuses:
     discovered          — seen in recon, not yet reviewed
     surface_reviewed    — skimmed/classified, no deep testing
     deep_reviewed       — agent or human tested with meaningful effort
     validated_signal    — interesting enough to route to a vuln lane
     dismissed           — intentionally deprioritized with reason

/url-ingest search <program> [--route-hash <hash>] [--param-hash <hash>]
                             [--host <host>] [--lane <lane>] [--limit <n>]
   Search URLs by route hash, param-shape hash, or host.

/url-ingest stats <program>
   Show DB statistics: total URLs, status breakdown, last import.

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
Before testing a URL in a lane, call `/url-ingest status` to check if it's already `deep_reviewed` or `dismissed` for that lane.

After testing, call `/url-ingest mark` to record the result.

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
xss, sqli, ssrf, idor, access-control, ssti, open-redirect, xxe, race, csrf
(Custom lanes are accepted; standard lanes are checked for typo warnings.)
