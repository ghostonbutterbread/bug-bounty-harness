# Bug Bounty Harness — Tool Reference

## Core Infrastructure

Shared modules imported by all harnesses.

### `agents/waf_interceptor.py`

Middleware that wraps all HTTP requests. Auto-detects 13+ WAF types and retries with bypass techniques when blocked. Integrated into `bypass_harness.py`; usable in any harness.

| Function / Class | Purpose |
|---|---|
| `WAFInterceptor(target, program)` | Core interceptor; target = base URL, program = output folder name |
| `interceptor.get(path, **kwargs)` | Sync GET with WAF auto-bypass (uses `requests`) |
| `interceptor.post(path, **kwargs)` | Sync POST with WAF auto-bypass |
| `await interceptor.aget(path, client=, **kwargs)` | Async GET with WAF auto-bypass (uses `httpx`) |
| `await interceptor.apost(path, client=, **kwargs)` | Async POST with WAF auto-bypass |
| `await interceptor.wrap_async(client, method, url, resp)` | Wrap an already-made async response — zero cost if not blocked |
| `interceptor.detect_waf(response)` | Returns `{"name", "confidence", "evidence"}` dict or `None` |
| `interceptor.stats` | Dict: total_requests, waf_blocks, bypass_success, bypass_fail |
| `interceptor.print_summary()` | Print human-readable stats |
| `WAFInterceptor.fingerprint(response)` | Class method — quick WAF name from response, no side effects |

**Detected WAFs:** Akamai, Cloudflare, AWS WAF/CloudFront, Imperva/Incapsula, F5 BIG-IP, Sucuri, Wordfence, ModSecurity, FortiWeb, Citrix NetScaler, DDoS-Guard, PerimeterX, DataDome

**Bypass techniques:** delay, User-Agent rotation (Chrome/iPhone/Googlebot/Bingbot), header injection (X-Forwarded-For, CF-IPCountry, etc.), path case variation, path prefix tricks, cookie passthrough

**Output:** `~/Shared/bounty_recon/{program}/ghost/waf/` → `blocks_log.txt`, `bypasses_log.txt`, `summary.json`

**Skill:** `skills/waf/SKILL.md`

---

### `agents/browser_block_fix.py`

Transparent curl → headless browser fallback middleware. Tries curl first (fast); on WAF block auto-spawns headless Chrome via Playwright and retries.

| Function / Class | Purpose |
|---|---|
| `BrowserBlockFix(target, program)` | Core middleware — target = base URL, program = optional label |
| `bbf.get(path, headers=None)` | GET: curl first, browser fallback if WAF blocks |
| `bbf.post(path, data=None, json=None, headers=None)` | POST: curl first, browser fallback if WAF blocks |
| `bbf.curl_get(path)` | Raw curl GET (no fallback logic) |
| `bbf.curl_post(path, data, json)` | Raw curl POST (no fallback logic) |
| `bbf.browser_get(path)` | GET directly through headless browser |
| `bbf.browser_post(path, data, json)` | POST through browser (form fill + submit) |
| `bbf.is_blocked(response)` | Returns `(True, "WafName")` or `(False, None)` |
| `bbf.spawn_browser()` | Launch headless Chrome (lazy import of Playwright) |
| `bbf.done()` | Close browser — call when finished |

**Detected WAFs:** Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, Wordfence, ModSecurity, FortiWeb, DDoS-Guard, PerimeterX, DataDome, F5 BIG-IP

**Response dict:** `{"success": bool, "status": int, "content": str, "headers": dict, "url": str, "via": "curl"|"browser"}`

**Dependencies:** `curl` (system), `playwright` (lazy — only imported on WAF block). Install: `pip install playwright && playwright install chromium`

**Skill:** `~/.openclaw/workspace/skills/browser/SKILL.md`

---

### `agents/rate_limiter.py`

Token bucket rate limiter for all HTTP requests and API calls.

| Function / Class | Purpose |
|---|---|
| `RateLimiter(rps, burst)` | Core rate limiter class |
| `limiter.wait()` | Blocking wait for a global token (sync) |
| `limiter.wait_for_host(host)` | Per-host rate limiting (global + per-host buckets) |
| `async with limiter.http()` | Async context manager for httpx/aiohttp requests |
| `limiter.adapt_to_response(resp)` | Auto-adjust from 429 / Retry-After / X-RateLimit-* headers |
| `create_http_limiter(program, target)` | Factory: program-aware limiter with conservative defaults |
| `create_api_limiter(api_name)` | Factory: pre-configured limiters for known APIs |
| `host_from_url(url)` | Extract hostname from a URL string |

**Pre-configured APIs:**

| API | Rate |
|---|---|
| crt.sh | 10 req/s |
| urlscan.io | 5 req/s |
| otx.alienvault.com | 20 req/s |
| bufferover | 10 req/s |
| whoxy | 2 req/s (varies by plan) |
| shodan | 1 req/s |
| censys | 2 req/s |
| virustotal | 0.25 req/s (free tier) |
| wayback / web.archive.org | 5 req/s |

**Features:** token bucket, burst capacity, per-host buckets, jitter, exponential backoff on 429, Cloudflare detection, thread-safe, async-compatible.

---

### `agents/scope_validator.py`

Validates that recon and testing targets stay within program scope.

| Function / Class | Purpose |
|---|---|
| `ScopeValidator(program, strict)` | Core validator — loads scope from standard file locations |
| `validator.is_in_scope(target)` | True/False check for hostname, IP, or URL |
| `validator.filter_in_scope(targets)` | Filter a list to only in-scope entries |
| `validator.filter_out_of_scope(targets)` | Inverse filter |
| `validator.partition(targets)` | Returns `(in_scope, out_of_scope)` tuple |
| `validator.validate_or_fail(target)` | Raises `OutOfScopeError` if not in scope (strict mode) |
| `validator.is_wildcard_scope(domain)` | True if `*.domain` is in scope |
| `validator.add_domain(domain)` | Manually add a domain/pattern to scope |
| `validator.get_domains()` | List all in-scope base domains |
| `scope_from_campaign(state)` | Build validator from a campaign.json state dict |
| `OutOfScopeError` | Exception raised by validate_or_fail() |

**Scope file locations (loaded in order):**
```
~/Shared/bounty_recon/{program}/scope/in-scope.txt
~/Shared/bounty_recon/{program}/scope/domains.txt
~/Shared/bounty_recon/{program}/scope/scope.txt
~/Shared/bounty_recon/{program}/recon/scope.txt
```

**Supported scope formats:**
```
example.com           # exact domain
*.example.com         # wildcard (matches api.example.com, x.y.example.com)
https://api.example.com/v1/*  # URL pattern with path prefix
10.0.0.0/8           # CIDR range (IP programs)
192.168.1.1          # single IP
# comment            # ignored
```

---

## Harness Modules

### `harness_core.py`
Core constraint enforcement. See `SPEC.md` for full schema.

| Class | Purpose |
|---|---|
| `HarnessConstraints` | Scope + rate + budget enforcement |
| `CampaignState` | Campaign JSON load/save/update with file locking |
| `HarnessViolation` | Exception for hard constraint violations |

### `baseline_capture.py`
Captures authenticated HTTP baselines before vulnerability testing.

### `test_catalog.py`
Loads bac_checks.py tests into campaign state.

### `verifier.py`
Reduces false positives by diffing baseline vs mutated responses.

---

## Agents

| Agent | Purpose |
|---|---|
| `agents/subdomain_agent.py` | Multi-source subdomain enum with takeover detection |
| `agents/xss_hunter.py` | XSS scanning with multi-type support |
| `agents/secrets_finder.py` | Secret/credential detection in JS, HTML, source |
| `agents/google_dorker.py` | Google dork automation |
| `agents/fuzz_runner.py` | Web fuzzing runner |
| `agents/autonomous_recon.py` | Autonomous recon orchestration |
| `agents/llm_harness.py` | LLM-assisted analysis harness |
| `agents/code_review.py` | Code review agent |
| `agents/payload_mutator.py` | Payload mutation for bypass testing |

---

## Bypass Harness (`agents/bypass_harness.py`) — Meta-Harness / Orchestrator

The bypass harness is now a **meta-harness** that orchestrates all bypass types.

### Two modes

```bash
# Full sweep — runs ALL bypass types in parallel (omit --type):
python3 bypass_harness.py --target "https://target.com/" --program myprogram

# Single type:
python3 bypass_harness.py --target "https://target.com/admin"        --type 403
python3 bypass_harness.py --target "https://target.com/api/user/123" --type idor
python3 bypass_harness.py --target "https://target.com/fetch?url=x"  --type ssrf      --param url
python3 bypass_harness.py --target "https://target.com/dl?file=x"    --type lfi       --param file
python3 bypass_harness.py --target "https://target.com/login?next=x" --type redirect  --param next
python3 bypass_harness.py --target "https://target.com/tpl?page=x"   --type traversal --param page
python3 bypass_harness.py --target "https://target.com/search?q=x"   --type ssti
python3 bypass_harness.py --target "https://target.com/redeem"       --type race
python3 bypass_harness.py --target "https://target.com/api.xml"      --type xxe
python3 bypass_harness.py --target "https://target.com/api"          --type cors
```

### Full sweep types (run in parallel, no --type needed)

| Type | Module | Detects |
|---|---|---|
| `cors` | `bypass_types/cors.py` | CORS misconfiguration (origin reflection, null, subdomain) |
| `xxe` | `bypass_types/xxe.py` | XML External Entity (file read, SSRF via entity, SVG bypass) |
| `ssrf` | inline (bypass_harness.py) | Server-Side Request Forgery (cloud IMDS, localhost, alt schemes) |
| `traversal` | `bypass_types/traversal.py` | Path traversal — basic file read (not full LFI) |
| `ssti` | `bypass_types/ssti.py` | Server-Side Template Injection (Jinja2, Twig, Freemarker, ERB, etc.) |
| `race` | `bypass_types/race.py` | Race condition / TOCTOU (concurrent duplicate requests) |
| `idor` | `bypass_types/idor.py` | Insecure Direct Object Reference (ID swapping, header tricks) |

### Single-type only (not in full sweep — use dedicated harnesses)

| Type | Notes |
|---|---|
| `403` | 403 Forbidden bypass (headers, path manipulation, method switching) |
| `lfi` | Local File Inclusion — use full `/lfi` harness for PHP wrappers etc. |
| `rfi` | Remote File Inclusion |
| `redirect` | Open redirect (3xx, JS/meta redirect) |
| `auto` | Auto-detect type from URL structure and parameter names |

### Output

```
~/Shared/bounty_recon/{program}/ghost/bypass/
├── full_sweep_{timestamp}.json   # Full sweep results (hits + misses)
├── full_sweep_{timestamp}.txt
├── {type}_{timestamp}.json       # Single-type results
├── {type}_{timestamp}.txt
└── summary.json                  # Latest hits only
```

---

## Bypass Modules (`agents/bypass_types/`)

| Module | Class | Tests |
|---|---|---|
| `cors.py` | `CORSBypass` | Origin reflection, null, subdomain confusion, wildcard+credentials |
| `xxe.py` | `XXEBypass` | Inline entity, parameter entity, SSRF via XXE, SVG context, error-based |
| `traversal.py` | `TraversalBypass` | Classic, URL-encoded, double-encoded, unicode, null-byte, Windows paths |
| `ssti.py` | `SSTIBypass` | Jinja2, Twig, Freemarker, Velocity, ERB, Slim, Razor, Smarty, config/class probes |
| `race.py` | `RaceBypass` | 15× concurrent duplicate requests, status/body variance analysis |
| `idor.py` | `IDORBypass` | Adjacent IDs, boundary IDs, UUID swap, header role escalation |

---

## Vuln Modules (`agents/vuln_modules/`)

| Module | Tests |
|---|---|
| `lfi.py` | Local File Inclusion |
| `bypass403.py` | 403 bypass techniques |
| `open_redirect.py` | Open redirect detection |
| `ssrf.py` | Server-Side Request Forgery |

## XSS Modules (`agents/xss_types/`, `agents/xss_bypasses/`)

XSS type detectors and bypass generators. See `agents/xss_types/` and `agents/xss_bypasses/` for individual modules.
