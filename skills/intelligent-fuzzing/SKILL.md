---
name: intelligent-fuzzing
description: "Targeted param/field discovery using tech stack clues, naming conventions, and controlled-rate ffuf — then feeds findings into request-exploration for mutation. Not brute-force; informed and scoped."
---

# Intelligent Fuzzing

Use when mapping a target app or testing a specific endpoint and you want to find hidden or undocumented parameters or fields. This is not brute-force spraying — it is targeted, informed discovery that feeds into `/request-exploration` for mutation after finding new parameters.

## Load Order

1. Read scope, owned-account context, and `/live-testing-policy`.
2. Confirm every account and resource is owned or explicitly approved.
3. Fingerprint the technology stack before selecting a wordlist.
4. Route focused lanes:
   - after discovery → `/request-exploration` for mutation
   - header-specific probing → `/headers`
   - WAF/filter behavior → `/waf-live-policy`

## Workflow

The methods below are **patterns to think with**, not a fixed checklist. Adapt them to the target's actual stack, naming conventions, and feature set. If the tech stack or app vocabulary suggests a discovery vector not listed here, try it.

### 1. Fingerprint the technology stack
Check HTTP headers (Server, X-Powered-By, CF-Ray), response body patterns, error page signatures, favicon hashes, JS file names, and Wappalyzer-equivalent signals. This guides wordlist selection.

Examples:
- `Server: nginx` + Django-style CSRF tokens → Django convention params like `csrfmiddlewaretoken`, `next`, `format`, `fields`.
- `X-Powered-By: Express` + `__callback` or `jsonp` in JS → Express/Node convention params like `callback`, `jsonp`, `_method`.
- Rails-style `authenticity_token` hidden inputs → Rails convention params like `utf8`, `commit`, `_method`, `format`.
- Next.js `__NEXT_DATA__` or `_next` paths → Next.js convention params like `__nextDefaultLocale`, `__nextLocale`, `amp`.
- GraphQL detected via `__schema` introspection or `/graphql` path → field names extracted from GraphQL schema or queries already observed.

### 2. Gather naming conventions
From already-observed requests: REST path patterns, GraphQL field names, query string keys, JSON body key styles (camelCase vs snake_case), and header naming patterns.

Examples:
- `/users/{id}` suggests `userId`, `user_id`, `user`, or `uid` as parameter names on other endpoints.
- `/api/orders/{orderId}/items` suggests `orderId`, `order_id`, `itemId`, or `item_id` on related endpoints.
- An observed JSON body using `customer_email` and `customer_name` suggests `customer_phone`, `customer_address`, `customer_role`, `customer_credit` may exist.
- Query strings consistently use `kebab-case` (e.g. `?sort-by=date`) — generate kebab-case variants for discovery.

### 3. Extract app/domain vocabulary
From crawled or mapped content: feature names, internal terms, admin/debug labels visible in the UI or JavaScript.

Examples:
- UI shows "Early Access" or "Beta" toggle → probe for `early_access`, `beta`, `feature_flag`, `eap`, `preview`.
- Admin panel visible in JS references `dashboard`, `impersonate`, `masquerade`, or `sudo` → add these to the wordlist.
- Error message says "Invalid plan type" → probe for `plan`, `plan_type`, `plan_id`, `subscription`, `tier`.
- JavaScript contains `debugMode`, `isDev`, `isSandbox`, or `mockUser` → probe these exact names plus lowercase/snake_case variants.

### 4. Build a targeted wordlist
Derived from the above, not a generic list. Include:
- Framework-specific params: Rails `authenticity_token`, Django `csrfmiddlewaretoken`, Express `__callback`, Laravel `_token`, Spring `_csrf`
- Admin/debug switches: `debug`, `preview`, `dev`, `test`, `admin`, `auth`, `sudo`, `impersonate`, `internal`, `mock`
- Feature flags: `beta`, `early_access`, `eap`, `preview`, `experimental`, `lab`, `hidden`
- Auth bypass: `isAdmin`, `isStaff`, `role`, `access`, `permission`, `scope`, `entitlement`
- Convention-based field names for the detected stack: snake_case for Python/Django, camelCase for JS/Node/Express, PascalCase for .NET

### 5. Probe with controlled rate
Default 15 rps, adaptive backoff on 429s, using ffuf or equivalent. Filter to in-scope paths only. Do not spray broadly.

Example ffuf invocation:
```bash
ffuf -w targeted.txt -u https://target.example.com/api/endpoint?FUZZ=test -H "Authorization: Bearer $TOKEN" -mc 200,201,301,302,401,403 -t 5 -p 0.2
```
Start with a small probe set derived from the tech stack and naming conventions. Expand only when the first wave produces useful signal without triggering rate limits or blocks.

### 6. Feed discoveries to `/request-exploration`
For each discovered parameter, run systematic mutation: boolean flip, type injection, encoding variants, and behavioral testing.

Example handoff:
- Intelligent fuzzing finds `?debug=true` returns a stack trace while `?debug=false` returns a normal page.
- Hand off to `/request-exploration`: try `1`, `yes`, `on`, `TRUE`, `%74rue`, `[true]`, and compare behavior at each value.

## Stop Conditions

Stop on: out-of-scope URL, non-owned resource without clear public access, human-facing action, program rate limit approached or persistent 429, excessive 4xx responses suggesting automated blocking, account lockout, or CAPTCHA.

## Evidence

Record tech stack signals found, wordlist rationale, parameters discovered, and any security-relevant behavior observed during mutation. Never record raw passwords, cookies, bearer tokens, or private data.