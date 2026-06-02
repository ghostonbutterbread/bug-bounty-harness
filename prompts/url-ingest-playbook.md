# url-ingest Playbook — Methodology

## Overview

The url-ingest system solves the "have we already looked at this URL?" problem for autonomous bug bounty hunting. It maintains a SQLite database per target program that tracks every discovered URL and its review state across vulnerability lanes.

## When to use it

### Pre-hunt ingestion
Before any hunting agents run against a program:
1. Run recon-ry on Hoster → produces `alive.txt`, `params_raw.txt`, etc.
2. Copy or pipe those files into url-ingest:
   ```bash
   ssh hoster 'cat /home/ryushe/bounties/<program>/alive.txt' | \
       python3 agents/url_ingest.py ingest <program>
   ```
3. Run `url-ingest stats <program>` to confirm import.

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
    --notes "GET /api/v2/users?id=1 returned 200 with full user list, confirmed IDOR" \
    --evidence "/home/ryushe/Shared/web_bounty/target/ghost/reports/idor/06-02-2026/canva-idor.png"
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

## Limitations (Phase 1)
- Fingerprinting (title, status code, content hash) is not yet stored
- Hoster → local sync is manual (scp or SSH pipe)
- DB lives on local disk, not P2P synced
- Large programs (500k+ URLs) will have slower query performance; future phase adds pagination/cursor

## Future phases
- Phase 2: Hoster rsync/ssh ingest, response fingerprinting, P2P sync
- Phase 3: Route clustering, auto-detection of untested param shapes, planner integration
