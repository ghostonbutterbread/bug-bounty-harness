# Summary — {program}

## Overview
Brief description of the program and scope.

## Scope
- **In-scope domains:**
  - target.com
  - api.target.com
- **Authentication required:** Yes/No
- **Rate limiting:** Yes/No (X requests per Y)

## Testing Status

| Category | Status | Last Tested | Notes |
|---------|--------|-------------|-------|
| XSS | 3/12 tested | 2026-03-30 | 1 confirmed, 2 potential |
| IDOR | 0/12 tested | — | — |
| SQLi | 2/12 tested | 2026-03-29 | No findings |
| SSRF | 0/12 tested | — | — |
| Auth | 1/8 tested | 2026-03-28 | Session tokens expire in 30min |

## Confirmed Findings
```
1. [HIGH] Stored XSS — /post/comment — @claude — 2026-03-30
2. [MEDIUM] Open Redirect — /redirect?url= — @ghost — 2026-03-28
```

## Potential Findings (Needs Verification)
```
1. [MEDIUM] Possible SSRF — /fetch?url= — @codex — 2026-03-29
```

## Last Session
- **Agent:** @claude
- **Date:** 2026-03-30
- **Work Done:** Tested XSS on all comment fields
- **Next Steps:** Test IDOR on /api/user/profile

---

*Auto-generated summary. Edit directly for corrections.*
