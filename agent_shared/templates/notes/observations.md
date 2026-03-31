# Observations — {program}

## WAF/Protection Behavior

```
WAF: Akamai
Bypasses detected: <script> blocked, <img onerror=> works
Rate limit: 10 req/sec after 100 requests
Blocking: Returns 403 after 5 failed logins
```

## Authentication Notes

```
Login endpoint: POST /api/auth/login
Session type: JWT in Authorization header
Session expiry: 30 minutes
CSRF required: Yes (X-CSRF-Token header)
```

## Interesting Endpoints

```
/api/v1/admin — Requires admin role (401 for regular users)
/api/internal — No auth, returns user data
/debug — Blocked by WAF
```

## Filter Observations

```
XSS filters: <script> stripped, <img onerror=> passes
SQLi filters: ' and " stripped
Reflected params: q, search, id (check each one)
```

## Testing Tips

```
- Use Google cached versions to bypass WAF
- Auth tokens expire fast — check before each session
- Start with low-and-slow to map rate limits
```

---

*Add observations as you discover them*
