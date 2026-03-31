# Web Fuzzing Playbook

## Overview
Web fuzzing — discovering hidden endpoints, parameters, and files through brute-force enumeration.

## Testing Approach

### 1. Directory/Endpoint Fuzzing
Discover hidden paths:
```
/admin
/api
/backup
/config
/debug
/.git
/.env
/internal
/test
/v1, /v2, /v3
```

### 2. Parameter Fuzzing
Discover hidden parameters:
```
?debug=1
?test=1
?id=1
?page=1
?redirect=
```

### 3. Subdomain Enumeration
```
api.target.com
staging.target.com
dev.target.com
internal.target.com
test.target.com
```

## Tools

### ffuf (Recommended)
```bash
ffuf -u https://target.com/FUZZ \
     -w wordlists/common.txt \
     -mc 200,204,301,302,307,401,403 \
     -fc 404 \
     -c -v
```

### Param Miner (for parameters)
```bash
python3 paramspider.py --target target.com
ffuf -u https://target.com/endpoint?FUZZ=test \
     -w wordlists/burp-parameter-names.txt \
     -fw 1
```

## Wordlists

| Purpose | Wordlist Location |
|---------|-----------------|
| Directories | `~/wordlists/SecLists/Discovery/Web-Content/common.txt` |
| Parameters | `~/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| Subdomains | `~/wordlists/commonspeak2/subdomains.txt` |
| APIs | `~/wordlists/SecLists/Discovery/Web-Content/api-endpoints.txt` |
| Sensitive Files | `~/wordlists/SecLists/Discovery/Web-Content/quick-fixes.txt` |

## Interesting Status Codes

| Code | Meaning |
|------|---------|
| 200 | Found! Analyze content |
| 204 | Empty response |
| 301/302/307 | Redirect — check where it goes |
| 401 | Auth required — could be IDOR vector |
| 403 | Forbidden — often interesting |
| 405 | Method Not Allowed — valid endpoint |

## Testing Workflow

1. **Run directory fuzz** — find interesting paths
2. **Follow redirects** — see where 301s go
3. **Fuzz parameters** — on interesting endpoints
4. **Analyze responses** — look for leaks, debug info
5. **Check for WAF** — slow down if blocked

## Fuzzing Categories

### Quick Wins (High Value)
```
/admin
/api/v1
/backup
/config
/debug
/.git/HEAD
/.env
/robots.txt
/sitemap.xml
/swagger
/graphql
```

### Sensitive Files
```
/wp-admin
/phpinfo.php
/info.php
/test.php
/debug.php
/backup.sql
/database.sql
/config.php.bak
```

## Findings Format

```
## Fuzz Finding
- **URL**: https://target.com/admin
- **Status**: 200 OK
- **Content Length**: 1234
- **Interesting**: Contains "Admin Panel"
- **Follow-up**: Test for auth bypass
```

## Files to Update
After finding interesting endpoints, write to:
```
~/Shared/bounty_recon/{program}/ghost/skills/fuzz/findings.md
```

Include: endpoint, status, content analysis, follow-up tests needed.
