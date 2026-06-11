# Error Mapper Playbook

## Purpose

Error Mapper helps a deep URL review learn how one URL handles unusual input
without turning into broad fuzzing. It is designed to run beside `/deep-hunt`,
`/recon_surface_map`, JavaScript review, and vulnerability-lane skills.

The goal is not "find SQLi with one quote." The goal is to map parser and
validation boundaries:

- which parameter is parsed server-side
- which parameter is ignored client-side
- which values change status, body length, redirect, content type, or visible
  error text
- which errors suggest routing to `/sqli`, `/ssti`, `/lfi`, `/headers`,
  `/waf`, `/bypass`, or source/JS review

## Preflight

Before probing:

1. Confirm the URL is in scope and safe for live testing.
2. Confirm the current account/resource is owned or non-sensitive.
3. Run or inspect the baseline request.
4. Read URL history:

```bash
python3 agents/url_ingest.py history <program> --url "<full-url>"
```

5. Choose at most a few parameters or path segments. Prefer fields with
   evidence from URL shape, JavaScript, live-map, forms, or API calls.

## Deep URL Loop Integration

For a single URL deep dive, the parent agent should gather:

- full URL and route shape
- related URLs from route hash or section cluster
- query/body/header fields
- linked JavaScript and endpoint construction
- baseline response status, length, content type, title, and visible error
- auth state and object ownership
- prior `/url-ingest history`

Then the agent may run a tiny error map only where it helps a hypothesis.

Example:

```text
H003 search?q
- evidence: q is passed into /api/search and rendered in SPA state
- baseline: 200, JSON, stable body length
- error-map subset: quote + semicolon only
- stop: any WAF/rate-limit, auth error, or response affecting non-owned data
```

## Probe Families

Choose the smallest useful subset.

### Quote Probe

Use when a value may enter SQL, template, JSON, HTML, search DSL, or server-side
parser code.

Characters:

```text
'
"
%27
%22
```

Signals:

- status changes
- framework/SQL/template/parser wording
- JSON parse errors
- escaping differences
- response length deltas that repeat once

### SQL-ish Separator Probe

Use only when a parameter is plausibly query/search/filter/sort/database-backed.

Characters:

```text
--
;
')
")
```

Signals:

- SQL grammar wording
- backend error with query/parser terms
- 500 only on SQL-ish fields, not control fields
- different behavior between `q`, `sort`, `filter`, `id`, or `cursor`

Route to `/sqli` only when there is a repeatable differential, not just a single
generic 400/500.

### Bracket and Template Probe

Use when a value may enter JSON, arrays, templates, markdown, GraphQL, or a
frontend/server render helper.

Characters:

```text
(
)
[
]
{
}
{{
}}
```

Signals:

- template/parser wording
- GraphQL or JSON validation errors
- frontend crash tied to route state
- sanitizer/render helper behavior

Route to `/ssti`, `/dom-xss`, `/headers`, or source/JS review depending on the
observed sink.

### Path Probe

Use only for path/file/template/download/page-like fields or route segments.

Characters:

```text
../
..%2f
%2e%2e%2f
```

Signals:

- path normalization difference
- file/path validation wording
- extension allowlist errors
- different behavior when encoded vs raw

Route to `/lfi`, `/bypass`, or `/headers` if the differential is repeatable and
the target is non-destructive.

### Null and Encoding Probe

Use when the parser may split, truncate, or normalize input.

Characters:

```text
%00
%2500
%2527
```

Signals:

- truncation
- backend validation mismatch
- different CDN/WAF vs origin behavior
- double-decoding hints

Route to `/waf`, `/bypass`, or the owning injection lane if the behavior is
specific and repeatable.

## Rate Limit

Default maximum for one URL:

- one baseline request
- one changed field per request
- no more than 5 to 8 total probe requests unless Ryushe explicitly asks for
  deeper testing
- pause between requests
- stop immediately on `429`, CAPTCHA, bot challenge, WAF escalation, account
  warning, or unexpected state change

## Recording

Use `url_ingest.py mark` after the small probe set:

```bash
python3 agents/url_ingest.py mark <program> \
  --url "<full-url>" \
  --lane recon \
  --status surface_reviewed \
  --skill error-mapper \
  --test-family parser-error-map \
  --technique quote-and-separator-baseline \
  --request-variant "changed q only with quote/semicolon subset" \
  --response-summary "baseline 200 JSON len 4210; quote 400 validation error; semicolon unchanged" \
  --notes "q appears server-validated; route to sqli only if repeatable on owned search flow."
```

Use `validated_signal` only when the response delta is concrete enough to hand
off:

```bash
python3 agents/url_ingest.py mark <program> \
  --url "<full-url>" \
  --lane sqli \
  --status validated_signal \
  --skill error-mapper \
  --test-family parser-error-map \
  --technique quote-probe \
  --response-summary "single quote repeats 500 with SQL grammar wording; baseline and double quote do not" \
  --notes "Route to /sqli for bounded confirmation."
```

## Handoff Card

```text
Error map:
- program:
- full URL:
- hypothesis ID:
- auth/account/resource ownership:
- baseline status/length/type:
- field tested:
- probe subset:
- changed response:
- repeatability:
- likely parser:
- route decision:
- stop condition:
```

## Stop Conditions

Stop and record a boundary when:

- rate limit, WAF, CAPTCHA, or bot challenge appears
- the request affects non-owned data or a destructive action
- the app sends account/security warnings
- the response includes sensitive data
- errors are generic and not repeatable
- the next step would require broad fuzzing instead of a bounded hypothesis
