---
name: proxy-curl
description: "Convert a saved raw proxy request into an auth-preserving curl replay while keeping method, URL, header order, cookies, content type, and body shape intact."
---

# Proxy Curl

Use when Ryushe gives an agent a saved proxy request, Caido/Burp raw request, or request text and expects a working `curl` replay instead of a guessed request.

This skill is a request-shape preservation skill. It does not decide whether a test is safe; load the owning testing skill and live-testing policy first when the replay will touch a live target.

## Load Order

1. Read scope, owned-account context, live-testing policy, and the owning skill for the security question.
2. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/proxy-curl-playbook.md`.
4. If a raw request is available as a file or pasted block, use:
   ```bash
   python3 "$HARNESS_ROOT/skills/proxy-curl/scripts/raw_to_curl.py" request.raw
   ```
5. Route results back to the owning skill:
   - one live request capture or mutation -> `/single-request-grabber`
   - header trust or parser behavior -> `/headers`
   - CSRF -> `/csrf`
   - IDOR or authorization boundary -> `/access-control` or `/idor`
   - WAF/client fingerprint issue -> `/waf` or proxy/browser fallback

## Workflow

1. Treat the saved request as the source of truth for method, path, host, cookies, X-* headers, content type, and body.
2. Build the full URL from `Host`, request target, and scheme. Use `https://` by default unless the capture proves plain HTTP.
3. Preserve header order from the raw request. Do not alphabetize headers.
4. Keep auth/session/context headers together exactly as captured, including `Cookie`, `Authorization`, CSRF headers, and product-specific X-* headers.
5. Keep all captured headers by default, including `Content-Length`, `Connection`, browser fetch metadata, `Priority`, and duplicate headers. Only drop framing headers with an explicit reason.
6. Send the exact body bytes/string with `--data-binary @file` for JSON, multipart, GraphQL, form, or opaque bodies.
7. For live replay, route `curl` through the resolved agent MITM proxy so the
   request is recorded. On OpenClaw/Ghost this usually means
   `curl -x http://hoster:8080 ...`; on Hoster or Ryushe's PC this usually
   means `curl -x http://localhost:8080 ...`. Use a leased per-agent proxy
   instead when the task needs isolated traffic.
8. Do not paste raw cookies, tokens, or generated auth-bearing curl commands into notes, reports, or chat.

## Stop Conditions

Stop if the request would perform a destructive action, touch non-owned data, use unclear account/resource ownership, replay stale one-time tokens repeatedly, or require bypassing bot/WAF controls beyond the approved test.

## Evidence

Record only sanitized shape: method, full URL, non-secret header names in original order, body field names, mutation, result, and artifact path. Do not store raw cookies, bearer tokens, CSRF tokens, or product session headers.
