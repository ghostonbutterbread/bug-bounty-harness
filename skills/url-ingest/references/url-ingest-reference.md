# URL Ingest Reference

## Locations

- Engine: `agents/url_ingest.py`
- Recon artifact recorder: `agents/recon_store.py`
- Playbook: `prompts/url-ingest-playbook.md`
- DB: `~/Shared/web_bounty/<program>/web/recon/url_index/url_index.sqlite`
- Aggregates: `~/Shared/web_bounty/<program>/web/recon/aggregated/`

## Canonical Aggregate Files

- `urls.txt` - all HTTP(S) URLs and exact URL-like targets
- `alive.txt` - probed live URLs/hosts; `live.txt` normalizes here
- `params_raw.txt` - raw parameterized URLs before final normalization
- `params.txt` - normalized parameterized URLs for vuln review
- `jsfiles.txt` - JavaScript URLs
- `wild.txt` - host/subdomain-shaped discoveries
- `dirs.txt` - directory/content-discovery leads

Standalone files are raw evidence. Aggregates and SQLite are shared working
state. `anew` prevents exact duplicate lines; `uro` reduces URL clutter; SQLite
canonicalization is authoritative for dedupe/review.

## Status Semantics

Statuses are per vulnerability lane:

| Status | Meaning |
|---|---|
| `discovered` | Seen in recon, not reviewed for this lane |
| `surface_reviewed` | Skimmed/classified, no deep testing |
| `deep_reviewed` | Meaningfully tested |
| `validated_signal` | Interesting enough to route to vuln lane |
| `dismissed` | Intentionally skipped with reason |

## Scoped Ingest

Prefer scoped imports for URLs that may feed live testing:

```bash
python3 agents/url_ingest.py ingest <program> --source urls.txt --run-id <run-id> --scope-filter auto
```

If saved scope exists, accepted/rejected temp files are written and only accepted
URLs are ingested. If no saved scope exists, auto mode tries the existing
pullscope engine across HackerOne, Bugcrowd, and Intigriti before fallback. If
scope still cannot be resolved, passive parsing may continue with
`scope_mode=no_scope_after_pull`; agents must not treat that as live-test
approval.

## Marking Coverage

Before a technique run, call `next` with `--skill` and `--test-family`; include
`--param` or `--param-preset` for parameter queues. After testing, call `mark`
with the lane, status, skill, test family, technique, parameter when relevant,
notes, evidence path, agent ID, and run ID.

## One-Off Recon Files

```bash
python3 agents/recon_store.py <program> --tool <tool-name> --target <domain-or-url> --source <artifact-file>
```

## Hoster Ingest

```bash
scp hoster:/home/ryushe/bounties/<program>/alive.txt /tmp/alive_<program>.txt
python3 agents/url_ingest.py ingest <program> --source /tmp/alive_<program>.txt --run-id <run-id>

ssh hoster 'cat /home/ryushe/bounties/<program>/alive.txt' | \
  python3 agents/url_ingest.py ingest <program>
```

## Supported Lanes

`recon`, `xss`, `sqli`, `ssrf`, `idor`, `access-control`, `ssti`,
`open-redirect`, `xxe`, `race`, `csrf`. Custom lanes are accepted; standard
lanes are typo-checked.
