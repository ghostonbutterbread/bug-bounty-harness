# URL Ingest Reference

## Locations

- Engine: `agents/url_ingest.py`
- Recon artifact recorder: `agents/recon_store.py`
- Playbook: `prompts/url-ingest-playbook.md`
- Review DB: `~/Shared/web_bounty/<program>/web/recon/url_index/url_index.sqlite`
- Recon-bus aggregates: `~/Shared/web_bounty/<program>/web/recon/aggregated/`

## Role Split

Recon-bus owns canonical aggregate promotion. Use `tool-run`,
`scripts/recon_bus.py append`, `promote-run`, or `watch-runs` when a discovery
or tool output should update shared recon inventory.

URL Ingest owns the SQLite review index. Use it when agents need to filter a
large URL set, select the next scoped review batch, check whether a URL or
parameter has already been inspected, or mark review/test coverage after work.

## Recon-Bus Inventory Files

- `urls.txt` - all HTTP(S) URLs and exact URL-like targets
- `alive.txt` - known live HTTP(S) URLs; `live.txt` normalizes here. Absence
  does not mean dead, and unprobed discoveries do not belong here.
- `params_raw.txt` - full HTTP(S) URLs with a query, before final normalization;
  never bare parameter names. Keep names and mining candidates in separate
  parameter-mining artifacts, not this URL queue.
- `params.txt` - derived normalized parameterized URLs for review; promotion
  uses it only when no `params_raw.txt` is present.
- `jsfiles.txt` - JavaScript URLs
- `wild.txt` - scope-maintained wildcard roots, not discovered hosts. Agents may
  maintain these from verified program scope through the existing explicit
  `append --kind wild` interface and its scope/wildcard validation. Tool output
  must not update scope roots: `promote-run` never classifies `wild.txt` as a
  discovery artifact.
- `hosts.txt` - all in-scope hostname inventory, regardless of HTTP liveness;
  do not filter this inventory by whether a host answered an HTTP probe.
- `dirs.txt` - directory/content-discovery leads

Standalone files are raw evidence. Recon-bus aggregates are shared recon
inventory. SQLite is shared review state. `anew` prevents exact duplicate lines
in aggregate stores; `uro` reduces URL clutter for `params.txt`; SQLite
canonicalization is authoritative for review dedupe and tested/untested state.
Recon-bus auto-indexes URL-shaped stores (`urls.txt`, `alive.txt`,
`params_raw.txt`, `jsfiles.txt`) into URL Ingest by default. Scope roots in
`wild.txt`, hostname inventory in `hosts.txt`, and leads in `dirs.txt` are not
live URL evidence and are not automatically inserted into the URL review index.

### Completed-run promotion boundary

`agents/recon/promote_run.py` owns the exact supported basename mapping (case
insensitive). Root, `normalized/`, `parsed/`, `raw/`, and manifest-declared files
use the same mapping; a manifest path does not authorize an arbitrary filename.
Existing plain-text aliases remain supported, including `js_urls.txt`,
`live-hosts.txt`, `url_seed.txt`, `javascript_urls.txt`, `all_urls.txt`, and the
manifest fixture's `url-output.txt`. Suffixes, backups, and substring matches
are not contracts.

`hosts.jsonl`, `httpx.jsonl`, `httpx_ip_raw.txt`, `waf_hosts.txt`, and
`unprotected_hosts.txt` are metadata/diagnostic artifacts, not plain-text queue
inputs. Port files (`ports.txt`, `port.txt`, `naabu.txt`, `ports.jsonl`,
`naabu.jsonl`) retain the separate JSON-aware port parser. The existing recursive
`dirs_status/` flat-result collection remains in place, including any historical
status directories inside the supplied run root. Only the scope/metadata names
listed above are excluded from that exception as well; normal status results
are unchanged. This repair does not migrate existing stores.

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
bbh agents/url_ingest.py ingest <program> --source urls.txt --run-id <run-id> --scope-filter auto
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
bbh agents/recon_store.py <program> --tool <tool-name> --target <domain-or-url> --source <artifact-file>
```

## Hoster Ingest

```bash
scp hoster:/home/ryushe/bounties/<program>/alive.txt /tmp/alive_<program>.txt
bbh agents/url_ingest.py ingest <program> --source /tmp/alive_<program>.txt --run-id <run-id>

ssh hoster 'cat /home/ryushe/bounties/<program>/alive.txt' | \
  bbh agents/url_ingest.py ingest <program>
```

## Supported Lanes

`recon`, `xss`, `sqli`, `ssrf`, `idor`, `access-control`, `ssti`,
`open-redirect`, `xxe`, `race`, `csrf`. Custom lanes are accepted; standard
lanes are typo-checked.
