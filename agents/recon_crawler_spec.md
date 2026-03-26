# Adaptive Recon Crawler Agent — SPEC

## Purpose

Harness-aware crawler that:
1. Discovers endpoints and parameters across the target
2. Adapts crawl depth based on what it finds
3. Tracks what's been crawled to avoid redundant work
4. Escalates when it finds high-value targets (auth endpoints, API routes, admin panels)
5. Feeds discovered endpoints into other agents (BAC tester, fuzz runner)

## Location

`~/workspace/bug_bounty_harness/agents/recon_crawler.py`

## State Shape (in campaign.json)

```json
{
  "recon_state": {
    "crawl_depth_reached": 2,
    "endpoints_discovered": ["/api/v2/users", "/admin/panel"],
    "params_discovered": ["user_id", "order_id", "page"],
    "domains_crawled": ["superdrug.com"],
    "last_crawl": "ISO timestamp",
    "depth_override": {"/api/v2/orders": 4, "/admin": 3},  // increase depth for juicy paths
    "session_start": "ISO timestamp"
  }
}
```

## Core Logic

```
1. Load campaign state + recon_state
2. Determine seed URLs from campaign["target"] and discovered endpoints

3. For each seed URL, crawl up to depth:
   - If path in depth_override: use that depth
   - Default: crawl_depth_reached from state

   - Fetch page (use httpx)
   - Extract: links, forms, params, JS files, API endpoints
   - If interesting (auth forms, API routes, admin panels):
     - escalate: add to depth_override for deeper crawl
     - flag as high-priority for other agents

4. Update recon_state with new discoveries
5. Update campaign["test_catalog"] endpoints if new ones found
6. Git commit
```

## Interesting Escalation Triggers

Escalate crawl depth (+2) when found:
- Authentication/registration forms
- API endpoints (`/api/`, GraphQL, REST routes)
- Admin panels or debug pages
- User-specific data pages (orders, messages, profile)
- File upload endpoints
- Payment/checkout flows

## Crawler Implementation

Use httpx with:
- Timeout: 10s per request
- Follow redirects: True
- Max redirects: 5
- Concurrent requests: 5 (avoid overwhelming target)
- User-Agent: Mozilla/5.0 compatible

Extract from HTML:
- `<a href>` links
- `<form action>` forms + inputs
- `<script src>` JS files
- `<link>` resources

Extract from JS:
- API endpoint patterns (fetch, axios, $.ajax calls)
- Hardcoded URLs
- Environment variables
- Token/secret patterns

## Output

Discovered data stored in:
- `campaigns/{id}/recon/endpoints_{timestamp}.json`
- `campaigns/{id}/recon/params_{timestamp}.json`
- `campaigns/{id}/recon/js_files_{timestamp}.json`

Findings flagged as category="recon" in potential findings.

## Integration

- Uses harness_core.HarnessConstraints
- Uses harness_core.CampaignState
- Updates campaign["test_catalog"] with discovered endpoints
- Feeds into bac_tester via test_catalog
- Git commits after each session

## CLI

```bash
python run_campaign.py run --campaign superdrug --agent recon
python run_campaign.py run --campaign superdrug --agent recon --depth 3
```
