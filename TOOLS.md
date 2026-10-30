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
| `interceptor.stats` | Dict: total_requests, observed_responses, client_call_failures, client_call_cancellations, waf_blocks, bypass_success, bypass_fail |
| `interceptor.print_summary()` | Print human-readable stats |
| `WAFInterceptor.fingerprint(response)` | Class method — quick WAF name from response, no side effects |

`total_requests` is a compatibility name for interceptor-owned client-call
attempts, including initial calls and retries that raise before transport. It is
not a count of actual sends or responses. `wrap_async` excludes its externally
supplied response and counts only retry calls it makes. `waf_blocks` counts
initial responses detected as blocks, including wrapped responses, so it does
not share a denominator with `total_requests`. The old block percentage was
removed; consumers must not treat the changed count as the previous logical-call
count. This interceptor's count is separate from the bypass guard's count.
`observed_responses`, `client_call_failures` and `client_call_cancellations`
classify completed interceptor-owned calls, not wire sends; a call in progress
is in `total_requests` but not yet in an outcome count. Cancellation during a
retry delay is not a client-call cancellation. For a program, `summary.json`
is initialized at zero and refreshed at attempts and outcomes, including
failures and cancellations. It is an instance snapshot, not a cumulative or
multiprocess aggregate: instances sharing a program overwrite the same file.
The file is ordinary synchronous I/O, not an atomic/crash-durable journal.
If a `summary.json` open/write/close raises `OSError`, the request still
proceeds or returns its original response, failure, or cancellation unchanged;
even when persistence is the only failure it is **not raised**. A sanitized
warning identifies the summary, numeric errno if available, stale/partial
snapshot risk, and storage/permission checks without paths or exception text.
`interceptor.summary_write_failures` counts failed flushes for the instance;
`interceptor.summary_last_errno` holds the last failure's integer errno or
`None`, even after a later successful flush. These diagnostics are in memory,
not a durable audit; logging configuration can suppress warnings. Directory
creation and the separate block/bypass log writes are not covered by this
summary-write contract. Consumers requiring durable accounting must check these
diagnostics and independently resolve the storage failure.

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
| `validator.is_wildcard_scope(domain)` | Valid declared wildcard root not wholly excluded; not a per-target authorization |
| `validator.add_domain(domain)` | Manually add a domain/pattern to scope |
| `validator.get_domains()` | List all in-scope base domains |
| `scope_from_campaign(state)` | Build validator from a campaign.json state dict |
| `OutOfScopeError` | Exception raised by validate_or_fail() |

**Scope file locations (loaded in order):**
```
~/Shared/scopes/{program}/in-scope.txt
~/Shared/scopes/{program}/rules-of-engagement.json  # platform/rules metadata
~/Shared/bounty_recon/{program}/scope/in-scope.txt  # legacy fallback
~/Shared/bounty_recon/{program}/scope/domains.txt   # legacy fallback
~/Shared/bounty_recon/{program}/scope/scope.txt     # legacy fallback
~/Shared/bounty_recon/{program}/recon/scope.txt     # legacy fallback
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

Optional host aliases such as `api(-eu1)?.example.com` expand to both
spellings. At most eight groups (256 variants) and 4096 characters are allowed
for host patterns containing `(`; excess raises rather than truncating a rule.
URL patterns are not expanded. The shared seed helper raises `ValueError` for
these limits; validator loads wrap parse failures in `ScopeAllowReadError` or
`ScopeExclusionReadError`, both `ScopeFileReadError` and `OSError`, with the
cause, file and line. Manual additions identify the entry kind and cause.

Genuinely absent standard files may fall back to legacy; dangling leaf or
ancestor symlinks and read failures do not. A file's entries are committed only
after its full read and parse; this is not an all-files transaction. After a
caught load/parse failure, Boolean scope checks refuse and `is_empty`,
`entry_count`, `get_domains` and `get_wildcards` raise the stored error.
Correct the source and construct a new validator. `strict=False` still warns
instead of enforcing `validate_or_fail`. Import the validator and exception
from the same module object: `scope_validator` and `agents.scope_validator` can
have distinct exception identities. If identity is unknown, catch `OSError` at
the load boundary and abort, never continue unscoped. Consumers must independently
enforce exclusions on every request and redirect; these checks are not a sandbox.

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
~/Shared/bounty_recon/{program}/agent_shared/findings/bypass/
├── full_sweep_{timestamp}.json   # Hits and counts
├── full_sweep_{timestamp}.txt    # Result entries
├── {type}_{timestamp}.json       # Single-type hits and counts
├── {type}_{timestamp}.txt
└── summary.json                  # Latest hits and counts
```

JSON `request_counts` dimensions are not all additive: `generated` counts
request-guard attempts and explicitly omitted mutations/initial scope denials;
`client_call_attempts` counts invocations of the underlying client, not proven
transport dispatch; `observed_responses` counts returned HTTP responses;
`skipped_scope` and `deferred` count scope denials or omitted mutations;
`unknown_failures` counts non-scope validation/client exceptions, whose
transport state may be unknown. WAF retries and baseline/detect calls are
included. The deprecated `dispatched` key is always `null` in JSON and `None`
in direct `BypassOrchestrator.request_counts` mapping access because wire
dispatch is not observable. `request_counts` is now a `RequestCounts` dict,
not a `Counter`: known dimensions are initialized to zero, unknown indexing
raises `KeyError`, and Counter arithmetic/default-zero semantics are gone.
Migrate readers to `client_call_attempts`, which is not proof of a send. `completed`
aliases `observed_responses`; `errors` aliases `unknown_failures`. Parent task
cancellation propagates and closes owned clients. An individually cancelled
`gather` probe is a no-response result (`status_code=0`, cancellation note),
not an observed response; race reports cancelled burst probes as an aggregate.
Cancellation of a client call after invocation remains included in attempts,
but not in responses or `unknown_failures`; transport state is unknown.
`KeyboardInterrupt` and `SystemExit` are not handled as probe failures. `total`
and the additive `result_count` count supplied result entries, not tested requests
or client calls. The summary now includes non-hit entries in that count because
it is written from all results rather than hits alone; `hits` still contains
successes only. `result_error_count` may include deferrals, and `execution_errors` can overlap
request failures. JSON `hits` contains successes only. Results now have an
additive `incomplete` boolean (default false). A race with a missing baseline,
or missing, failed or cancelled burst probes, is incomplete: a non-hit renders
`[unknown]`, not `[miss]`, even if some HTTP responses were observed. A hit
based on partial observations remains a hit but is marked `[incomplete]`.
Race notes distinguish observed, no-response, cancelled, and unobserved counts;
the no-response count includes cancellations. The additive JSON
`incomplete_results` array includes incomplete hits and non-hits (and can
overlap `hits`); legacy readers using only `hits` cannot see incomplete
non-hits. The Python `run_and_report` tuple retains incomplete non-hits in its
second, historically named failures list; `success=False` alone is not proof
of a complete negative. Parent cancellation still propagates without a result.

Result URLs and logs suppress query values; request URLs sent to HTTPX are not
redacted or rewritten by this output projection. The `BypassResult` Python
contract and text/JSON reports retain status, type, technique, category,
redacted payload and derived notes but replace raw response-body/header evidence
with a withholding marker. CORS evidence retains only derived ACAO classification
(reflected, wildcard, other or absent) and credentials boolean; race evidence
retains baseline status, status counts, error count and number of body variants.
Other evidence defaults to withholding. This is an intentional compatibility change: raw
response snippets are no longer available through these results. No raw response
artifact is retained by this harness. Recognized credentials, cookies and
secret-like fields are redacted with the shared evidence redactor and additional
conservative output masking. This is **not** a guarantee of detecting arbitrary
secrets in paths, unstructured payloads, notes, program names or other data;
treat all output as potentially sensitive and review before sharing. Do not use
these projections as exact replay requests. WAF logs use the same best-effort
redaction. Access to raw evidence requires a separately authorized protected
capture workflow, not these reports.

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
