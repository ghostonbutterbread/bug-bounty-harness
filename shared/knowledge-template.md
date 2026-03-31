# Universal Bug Bounty Knowledge Store

This is the **shared knowledge base** for all agents working on this program.
Every agent should read this file before starting work and write findings here when done.

## Program Quick Summary

**Target:** `{program_name}`
**Scope:** `{list of in-scope domains}`
**WAF:** `{Akamai / Cloudflare / None / Unknown}`
**Auth Type:** `{session cookie / JWT / OAuth / None}`

---

## What's Been Tested

### XSS
- **Status:** `{pending / in-progress / complete}`
- **Endpoints tested:** `{list}`
- **Filters found:** `{any WAF/filter observations}`
- **Bypasses discovered:** `{list}`
- **Last tested:** `{date}`

### IDOR
- **Status:** `{pending / in-progress / complete}`
- **Endpoints tested:** `{list}`
- **Object IDs found:** `{sequential / UUID / etc}`
- **Last tested:** `{date}`

### SQL Injection
- **Status:** `{pending / in-progress / complete}`
- **Endpoints tested:** `{list}`
- **Error patterns found:** `{list}`
- **Last tested:** `{date}`

### SSRF
- **Status:** `{pending / in-progress / complete}`
- **Endpoints tested:** `{list}`
- **Internal services accessible:** `{list}`
- **Last tested:** `{date}`

### Fuzzing
- **Status:** `{pending / in-progress / complete}`
- **Directories found:** `{list}`
- **Hidden endpoints:** `{list}`
- **Last tested:** `{date}`

---

## Known Findings

### Confirmed
| Vuln | Endpoint | Description | Reported |
|------|----------|-------------|----------|
| | | | |

### Potential (Needs Verification)
| Vuln | Endpoint | Description | Notes |
|------|----------|-------------|-------|

---

## Observations

### WAF/Filter Behavior
```
- {Akamai blocks after X requests}
- {Cloudflare requires user-agent match}
- {Filter: <script> blocked, <img onerror=> works}
```

### Authentication
```
- Login endpoint: POST /api/auth/login
- Session expires: {time}
- CSRF token: {required / not required}
```

### Interesting Endpoints
```
- /api/v1/admin (requires auth)
- /api/internal (no auth, leaked data)
```

---

## What's Next

### Priority Testing
1. {vulnerability type} on {endpoint}
2. {vulnerability type} on {endpoint}
3. {vulnerability type} on {endpoint}

### Notes for Next Agent
```
- {Any important context for continuing work}
- {Known issues with auth}
- {WAF behavior to be aware of}
```

---

## File Locations

| Skill | Findings Location |
|-------|------------------|
| XSS | `~/Shared/bounty_recon/{program}/ghost/skills/xss/findings.md` |
| IDOR | `~/Shared/bounty_recon/{program}/ghost/skills/idor/findings.md` |
| SQLi | `~/Shared/bounty_recon/{program}/ghost/skills/sqli/findings.md` |
| SSRF | `~/Shared/bounty_recon/{program}/ghost/skills/ssrf/findings.md` |
| Fuzz | `~/Shared/bounty_recon/{program}/ghost/skills/fuzz/findings.md` |
| Recon | `~/Shared/bounty_recon/{program}/ghost/skills/recon/findings.md` |

---

*Last updated: {date} by {agent_name}*
