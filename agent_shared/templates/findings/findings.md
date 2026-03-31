# Findings Template — {vuln_type}

## How to Write Findings

Use the generic skeleton for every finding, then keep only the vuln-specific detail block that matches the issue you are reporting. Delete the other blocks or mark them `N/A`.

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

### Generic Evidence
Use for all finding types.

```
vector: query / body / JSON / header / cookie / path / workflow / other
baseline: how the endpoint behaved before mutation
evidence: key response delta, timing delta, state change, or artifact path
artifacts: screenshots, raw reports, PoC HTML, or harness output paths
```

### Vulnerability Details
Choose the matching block below.

#### XSS Details
```
reflection_context: HTML body / quoted attribute / unquoted attribute / JS string / template literal / URL / CSS / DOM source-to-sink / N/A
sink: innerHTML / eval / dangerouslySetInnerHTML / v-html / bypassSecurityTrustHtml / N/A
bypass_used: None / encoding / case mutation / separator trick / event swap / framework-specific bypass
browser_verified: Yes / No
required_interaction: None / victim loads page / click / hover / admin review / other
cleanup_needed: Yes / No
```

#### SQLi Details
```
sqli_type: error / boolean / time / union / N/A
db_family: MySQL / PostgreSQL / MSSQL / Oracle / SQLite / Unknown
db_evidence: error fragment / timing primitive / reflected constant / other
filter_or_waf: None / keyword strip / quote strip / WAF block / other
non_destructive: Yes / No
```

#### SSRF Details
```
ssrf_type: direct / redirect / parser-confusion / metadata / alternate-scheme / blind
sink_parameter: url / src / callback / webhook / other
destination_class: loopback / RFC1918 / metadata / internal service / file / controlled host
redirect_or_header_requirement: None / redirect / metadata header / other
impact_boundary: reachability only / metadata root / internal service banner / local file marker
```

#### IDOR Details
```
idor_type: horizontal-read / horizontal-write / vertical / workflow
object_reference: path ID / query param / JSON field / hidden field / token
caller_context: user / role / tenant used for the test
unauthorized_target: peer user / admin object / cross-tenant object / workflow object
state_change: none / read / update / delete / transition
```

#### Fuzz Details
```
fuzz_lane: path / extension / parameter / vhost
status_signal: 200 / 301 / 302 / 307 / 401 / 403 / 405 / other
response_size_signal: baseline delta or notable size
interesting_reason: admin surface / debug / docs / config / backup / auth boundary / other
next_step: recon only / verify auth / verify secrets / fuzz params / other
```

#### Recon Details
```
recon_type: technology / endpoint / parameter / JS asset / secret / WAF / open port / other
seed_target: host or domain scanned
surface_change: what new attack surface was added to the map
follow_on_modules: xss / idor / sqli / ssrf / fuzz / waf / race / csrf / other
artifact_files: urls.txt / params.txt / js_files.txt / tech_stack.txt / summary.json / other
```

#### WAF Details
```
waf_name: Cloudflare / Akamai / AWS WAF / Imperva / ModSecurity / Unknown
trigger_type: rate / path / header / payload / cookie / challenge
blocked_response: status and signature observed
bypass_technique: delay / UA rotation / header change / path trick / payload obfuscation / none
origin_delta: status, body, or header difference after bypass
```

#### Race Details
```
race_type: duplicate-use / limit-bypass / toctou / workflow-conflict
preconditions: token, balance, item, or workflow state required
concurrency: request count and method used
baseline_result: normal single-request outcome
raced_result: duplicated acceptance / inconsistent state / mixed responses / other
committed_impact: duplicate credit / overuse / invalid transition / none
```

#### CSRF Details
```
csrf_type: missing-token / weak-token / samesite / origin-referer / request-shape-downgrade
token_behavior: absent / accepted when omitted / replayable / cross-session / cookie-duplicated / bound correctly
cookie_posture: SameSite=None / Lax / Strict / unset / other
origin_referer_behavior: not checked / weakly checked / correctly checked / inconsistent
required_interaction: none / victim visits page / click / navigation / other
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

*Add new findings above this line*
