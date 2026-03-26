# Adaptive Fuzz Agent — SPEC

## Purpose

Harness-aware fuzzing agent that:
1. Runs ffuf with state persistence across sessions
2. Adapts wordlist based on findings
3. Tracks rate limits and backs off automatically
4. Skips already-tested paths
5. Escalates when interesting things are found

## Location

`~/workspace/bug_bounty_harness/agents/fuzz_runner.py`

## Interface

```python
from agents.fuzz_runner import FuzzAgent

agent = FuzzAgent(campaign_id)
agent.run(max_requests=500)  # runs until budget or completion
```

## State Shape (in campaign.json)

```json
{
  "fuzz_state": {
    "wordlist_idx": 0,
    "wordlist_paths": ["~/wordlists/SecLists/Discovery/Web-Content/common.txt"],
    "paths_tested": ["/admin", "/api"],
    "targets_tested": ["https://api.example.com"],
    "findings_interesting": 0,
    "rate_limit_events": 0,
    "backoff_until": null,
    "session_start": "ISO timestamp",
    "last_wordlist": "path to wordlist"
  }
}
```

## Core Logic

```
1. Load campaign state + fuzz_state
2. Check backoff — if rate-limited, sleep or defer

3. Determine wordlist:
   - If recent_interesting_findings > 0: bump wordlist_idx (use bigger/better list)
   - Else: use current wordlist

4. For each target URL in scope:
   - For each path from wordlist (skip if already tested):
     - enforce scope constraint
     - enforce rate limit
     - check budget
     - run: ffuf -u TARGET/FUZZ -w WORDLIST [flags]
     - record result
     - if 403/429: backoff, break
     - if interesting (200 with content, 301/302, 401/403 on admin paths):
       - flag as interesting, add to findings
       - mark path as interesting in paths_tested

5. Update fuzz_state in campaign.json
6. Git commit
```

## ffuf Configuration

Default flags:
```
-t 20              # threads
-mc 200-299,301,302,307,401,403,405,500  # interesting codes
-fc 404            # filter 404s
-fs 0              # filter size 0 (blank pages)
-c -v              # color, verbose
```

Rate-sensitive targets (WAF detected):
```
-t 5               # reduce threads
-r                 # follow redirects
```

## Interesting Findings

Flag these automatically:
- 200 responses with unusual content length (potential config files: `.env`, `.git`, `backup`)
- 301/302/307 redirects (especially to internal paths)
- 401/403 responses (auth bypass candidates)
- 405 Method Not Allowed (good endpoints with wrong method)
- 500 Internal Server Error (injection candidates)
- Paths containing: `admin`, `api`, `debug`, `test`, `config`, `backup`, `internal`, `v1/v2/v3`, `.env`, `.git`, `swagger`, `metrics`

## Rate Limit Handling

```
if http_code == 429:
    campaign["fuzz_state"]["backoff_until"] = time.time() + 60
    campaign["fuzz_state"]["rate_limit_events"] += 1
    campaign["fuzz_state"]["wordlist_idx"] = max(0, wordlist_idx - 1)  # slow down wordlist
    # break this session, agent will resume later
```

## Integration

- Uses harness_core.HarnessConstraints for scope/rate/budget enforcement
- Uses harness_core.CampaignState for state persistence
- Findings stored in campaign["findings"]["potential"] with category="fuzz"
- Raw ffuf output saved to campaigns/{campaign_id}/fuzz_raw_{timestamp}.txt
- Interesting findings summary saved to campaigns/{campaign_id}/fuzz_findings_{timestamp}.txt

## CLI Integration

```bash
python run_campaign.py run --campaign superdrug_20260326 --agent fuzz
python run_campaign.py run --campaign superdrug_20260326 --agent fuzz --max-requests 100
```
