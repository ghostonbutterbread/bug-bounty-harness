# Server Errors

Use for `500`, `502`, `503`, stack traces, reverse-proxy errors, framework pages, server banners, and infrastructure disclosures.

## Checks

- Capture status, error page title, server headers, request ID, framework names, stack paths, and proxy/CDN hints.
- Retry once with the minimal same request to distinguish transient failures from deterministic behavior.
- Identify the input segment most likely causing the error.
- If server technology is leaked, record it and route to source review, `/fuzz`, `/headers`, or the relevant vuln lane.

## Route

- stack/framework leak with controllable input -> relevant injection/parser lane
- Apache/Nginx/proxy route behavior -> `/headers` or `/fuzz`
- deterministic route crash -> note for deeper owned-scope testing
- temporary upstream outage -> record and stop

## Evidence Required

- Minimal reproducer.
- Error markers and headers.
- Whether the error is deterministic.
- Security relevance beyond "server returned 500".

## Stop

Stop before stress testing, crash loops, high-volume retries, or extracting secrets from stack traces/logs.
