# url-ingest Playbook — Methodology

## Overview

The url-ingest system solves the "have we already looked at this URL?" problem for autonomous bug bounty hunting. It maintains a SQLite database per target program that tracks every discovered URL and its review state across vulnerability lanes.

Recon tools must follow the unified recon-store rule:

1. Preserve raw tool output in canonical recon run storage.
2. Extract only URL/host-shaped lines into parsed artifacts.
3. Import parsed URL artifacts into the SQLite URL index.
4. Have downstream agents query `stats`, `next`, `status`, or the recon run manifest before loading large queues.

This applies even when Ryushe runs a one-off tool such as amass. The one-off output should be recorded with `agents/recon_store.py` instead of left as an isolated text file.

## When to use it

### Pre-hunt ingestion
Before any hunting agents run against a program:
1. Run recon-ry on Hoster → produces `alive.txt`, `params_raw.txt`, etc.
2. Copy or pipe those files into url-ingest. For queues that may feed live testing, scope-filter first:
   ```bash
   ssh hoster 'cat /home/ryushe/bounties/<program>/alive.txt' | \
       python3 agents/url_ingest.py ingest <program> \
         --run-id <run-id> \
         --scope-filter auto
   ```
3. Run `url-ingest stats <program>` to confirm import.

For an agent-safe overview before selecting work, use:

```bash
python3 agents/url_ingest.py brief <program> --limit 20
```

This prints totals, top hosts, common parameter keys, and recent imports without dumping the full URL table.

For generic recon output files, use the shared recorder:

```bash
python3 agents/recon_store.py <program> \
  --tool amass \
  --target example.com \
  --source /path/to/amass-subs.txt
```

The recorder copies the raw file, extracts URL/host-shaped lines when the artifact type is known to contain them, imports those parsed lines into SQLite, and writes a manifest under canonical `~/Shared/web_bounty/<program>/web/recon/<tool>/...` storage.

Scope behavior:

- If saved scope exists, `url-ingest` writes accepted/rejected temp files under `/tmp` and ingests only accepted URLs.
- If no saved scope exists and `--scope-filter auto` is set, it tries the existing `agents/scope_puller.py` against public HackerOne, Bugcrowd, and Intigriti before fallback.
- If no scope can be found after repull, passive parsing is allowed and the import is labeled `scope_mode=no_scope_after_pull`. Agents must notify Ryushe before live testing because no authoritative scope was established.
- If scope filtering is intentionally not wanted, omit `--scope-filter auto`; the import will be labeled `scope_filter_off`.
- If an agent needs scoped temp files but must intentionally skip repull, use `--no-repull-scope`; this should be rare and treated as passive/import-only.

Inspect import metadata through `stats`; it includes read, accepted, rejected, scope mode, and temp file paths.

### Pre-test query
Before an agent tests a URL in lane `X`, check if it's already been reviewed:
```bash
python3 agents/url_ingest.py status <program> --lane xss --url "https://target.com/api/v2/users?id=1"
```
If status is `deep_reviewed` or `dismissed` for that lane → skip or note.

### Post-test recording
After testing, record what was done:
```bash
python3 agents/url_ingest.py mark <program> \
    --url "https://target.com/api/v2/users?id=1" \
    --lane idor \
    --status deep_reviewed \
    --skill access-control \
    --test-family object-ownership \
    --technique "cross-account-id-swap" \
    --notes "GET /api/v2/users?id=1 returned 200 with full user list, confirmed IDOR" \
    --evidence "/home/ryushe/Shared/web_bounty/target/ghost/reports/idor/06-02-2026/canva-idor.png"
```

`mark` has two effects:
- appends a permanent row to `test_runs`
- updates the one-row `observations` summary for fast skip/route decisions

Do not rely on `observations` as the audit trail. Use `history` for the audit trail.

### Technique-specific queueing
Before running one technique across a batch, ask for URLs that have not yet seen that technique:

```bash
python3 agents/url_ingest.py next <program> \
  --lane recon \
  --skill user-agent-fuzz \
  --test-family header-behavior \
  --limit 25
```

For parameter-injection lanes, use parameter-aware presets so agents do not all receive the same generic first-seen queue:

```bash
python3 agents/url_ingest.py next <program> \
  --lane xss \
  --skill xss \
  --test-family reflected-probe \
  --param-preset xss \
  --limit 25

python3 agents/url_ingest.py next <program> \
  --lane ssrf \
  --skill ssrf \
  --test-family url-fetcher-probe \
  --param-preset ssrf \
  --limit 25

python3 agents/url_ingest.py next <program> \
  --lane lfi \
  --skill lfi \
  --test-family path-traversal-probe \
  --param-preset lfi \
  --limit 25
```

Preset intent:

- `xss`: text/search/content-ish parameters such as `q`, `query`, `search`, `title`, `name`, `content`
- `ssrf`: URL/redirect/callback-ish parameters such as `url`, `redirect`, `callback`, `loginRedirect`, `signupRedirect`
- `lfi`: path/template/page-ish parameters such as `file`, `path`, `template`, `page`, `include_page_ids`
- `opaque-state`: encoded state/routing parameters such as `ui`, `adj`, `category`, `type`

Examples of useful skill/test-family pairs:

- `user-agent-fuzz` / `header-behavior`
- `param-fuzz` / `parameter-mining`
- `js-static-analysis` / `endpoint-and-sink-map`
- `xss` / `reflected-probe`
- `ssrf` / `url-fetcher-probe`
- `access-control` / `object-ownership`

After the technique runs, record the actual test:

```bash
python3 agents/url_ingest.py mark <program> \
  --url "https://target.example/search?q=test" \
  --lane recon \
  --status surface_reviewed \
  --skill user-agent-fuzz \
  --test-family header-behavior \
  --technique desktop-vs-mobile-agent \
  --request-variant "changed User-Agent only" \
  --response-summary "status and response length unchanged" \
  --notes "No behavior delta."
```

Use `history` to inspect all tests logged for one URL:

```bash
python3 agents/url_ingest.py history <program> --url "https://target.example/search?q=test"
```

### Route-based dedup
Instead of tracking every URL individually, agents can query by route hash to find related URLs:
```bash
# Get route hash from a URL
python3 -c "
from agents.url_ingest import url_hashes
print(url_hashes('https://target.com/api/v2/users?id=1')[1])
"
```
This returns the route hash — use it to find all URLs sharing the same path pattern.

## Depth classification guidelines

| Depth | When to use |
|-------|-------------|
| `discovered` | Auto-assigned on ingest. Never set manually. |
| `surface_reviewed` | Looked at the URL briefly (title, status code, response size). No payloads sent. |
| `deep_reviewed` | Ran one or more payloads / functional tests. |
| `validated_signal` | Found something worth investigating further. Route to the relevant lane. |
| `dismissed` | Intentionally skipped. MUST include reason in `--notes`. |

## Workflow integration

### With zero_day_team / XSS hunter
```python
# In a lane agent, before testing:
status = subprocess.run([
    "python3", "agents/url_ingest.py", "status", program,
    "--lane", "xss", "--url", url
], capture_output=True, text=True)
if "deep_reviewed" in status.stdout or "dismissed" in status.stdout:
    return  # skip

# ... run tests ...

# After tests:
subprocess.run([
    "python3", "agents/url_ingest.py", "mark", program,
    "--url", url, "--lane", "xss", "--status", "deep_reviewed",
    "--notes", "...", "--evidence", evidence_path
])
```

### With recon planner
The recon planner pulls `discovered` URLs or stale `surface_reviewed` URLs to generate fresh hunting tasks, preventing agents from re-testing already-reviewed surfaces.

When the planner assigns a technique, it should use `next` with the skill/test-family fields rather than only checking lane status. This lets different agents test the same URL for different hypotheses without overwriting each other.

## Limitations (Phase 1)
- Fingerprinting (title, status code, content hash) is not yet stored
- Hoster → local sync is still explicit, but `recon_ry.py ingest` now imports copied URL artifacts into SQLite automatically
- DB lives on local disk, not P2P synced
- Large programs (500k+ URLs) will have slower query performance; future phase adds pagination/cursor

## Future phases
- Phase 2: Hoster rsync/ssh ingest, response fingerprinting, P2P sync
- Phase 3: Route clustering, auto-detection of untested param shapes, planner integration
