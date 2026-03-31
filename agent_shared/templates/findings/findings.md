# Findings Template — {vuln_type}

## How to Write Findings

Every finding should have these sections. Be concise but complete.

---

## Finding: {Brief Title}

**Severity:** Critical / High / Medium / Low / Informational  
**Status:** Confirmed / Potential / False Positive  
**Found by:** @agent  
**Date:** YYYY-MM-DD

### Target
```
URL: https://target.com/endpoint
Parameter: param_name (GET/POST)
Method: GET/POST/PUT/DELETE
```

### Description
What the vulnerability is and where it exists.

### XSS Details
Use this section for XSS findings. Leave `N/A` when a field does not apply.

```
reflection_context: HTML body / quoted attribute / unquoted attribute / JS string / template literal / URL / CSS / DOM source-to-sink / N/A
sink: innerHTML / eval / dangerouslySetInnerHTML / v-html / bypassSecurityTrustHtml / N/A
bypass_used: None / encoding / case mutation / separator trick / event swap / framework-specific bypass
confirmed: Yes / No
browser_verified: Yes / No
required_interaction: None / victim loads page / click / hover / admin review / other
cleanup_needed: Yes / No
```

### PoC
```
Step 1: Navigate to URL
Step 2: Modify parameter X to value Y
Step 3: Observe result Z
```

### Impact
Security impact to the application and users.

### Remediation
How the developers should fix it.

### References
- CVE links (if applicable)
- Relevant documentation
- Similar findings/writeups

---

## Example Finding: Stored XSS in Comment Field

**Severity:** High  
**Status:** Confirmed  
**Found by:** @claude  
**Date:** 2026-03-30

### Target
```
URL: https://target.com/post/123/comment
Parameter: comment (POST)
Method: POST
```

### Description
The comment field on blog posts does not sanitize HTML. Payload `<script>alert(1)</script>` is stored and executes when viewed.

### XSS Details
```
reflection_context: HTML body
sink: innerHTML
bypass_used: None
confirmed: Yes
browser_verified: Yes
required_interaction: Victim loads the post page
cleanup_needed: Yes
```

### PoC
```
1. Navigate to https://target.com/post/123
2. Submit comment: <script>alert(document.cookie)</script>
3. View the post — script executes
```

### Impact
An attacker could steal session cookies, redirect users, or modify page content for all viewers.

### Remediation
Sanitize HTML input, use Content Security Policy, escape user input in responses.

---

*Add new findings above this line*
