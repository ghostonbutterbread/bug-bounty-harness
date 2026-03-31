# Testing Checklist — {program}

## How to Update

After testing a vulnerability type, mark it as:
- `[x]` — Tested (findings or cleared)
- `[ ]` — Not yet tested
- `[P]` — In progress

Format: `[x] VULN_TYPE — Brief note (confirmed/cleared/found nothing)`

---

## Critical Vulnerabilities

- [ ] **IDOR** — Insecure Direct Object Reference (horizontal/vertical)
- [ ] **Broken Auth** — Session management, password reset, login bypass
- [ ] **Privilege Escalation** — Admin actions as regular user

## High Vulnerabilities

- [ ] **XSS** — Reflected, Stored, DOM-based
- [ ] **SQLi** — Error-based, Blind, UNION
- [ ] **SSRF** — Server-Side Request Forgery
- [ ] **XML External Entity (XXE)** — If XML endpoints found
- [ ] **Command Injection** — OS command injection in params

## Medium Vulnerabilities

- [ ] **CSRF** — Cross-Site Request Forgery
- [ ] **Open Redirect** — Unvalidated redirects
- [ ] **CORS Misconfiguration** — Cross-origin resource sharing
- [ ] **Race Conditions** — TOCTOU vulnerabilities
- [ ] **Business Logic** — Application-specific flaws
- [ ] **API Misconfigurations** — REST/GraphQL issues

## Information Disclosure

- [ ] **Directory Traversal** — Path traversal in file params
- [ ] **Git/SVN Exposure** — .git/.svn directories accessible
- [ ] **Debug Pages** — /debug, /actuator, /env
- [ ] **Server Version Disclosure** — Banner grabbing
- [ ] **Source Code Leak** — Exposed config files

## Low/Hinformational

- [ ] **Clickjacking** — Missing X-Frame-Options
- [ ] **Missing Security Headers** — CSP, X-Content-Type, etc.
- [ ] **Weak SSL/TLS** — HTTPS configuration issues
- [ ] **EmailEnumeration** — User existence disclosure

---

## Notes

```
Add testing notes here:
- What was tested and when
- Interesting findings during testing
- False positives to ignore
```

---

*Last updated by: {agent}*
*Date: {date}*
