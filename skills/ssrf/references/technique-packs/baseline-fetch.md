# Baseline, Blind, Async, and Secondary Fetchers

Use before filter bypasses or whenever a URL may be processed by a worker rather
than the synchronous request. Confirm the **server**, not the browser, fetched
it.

## Controlled detection channels

Use an owned endpoint and a unique canary path. Record separately:

- DNS lookup, TCP connection, and HTTP callback;
- timestamp, source address class, method, HTTP version, headers, redirect
  following, and retry behavior;
- reflected body/status/header, job status, queue delay, cache effect, or
  downstream notification; and
- a controlled reachable versus unreachable timing comparator.

DNS-only evidence proves resolver reachability, not necessarily an HTTP request.
A client-side navigation, generic error, or unrepeatable timeout is not SSRF.

## Secondary-fetcher inventory

Exercise the trigger and then revisit it after the original request:

- link preview/unfurl, analytics (`Referer`/user-agent), webhooks, integrations,
  email/PDF/screenshot and browser-rendering workers;
- image proxy/resize, media/document conversion, XML/SVG/XSLT, feed/sitemap,
  repository/package/API-schema import, and archive processing; and
- cache warmers, malware scanners, CDNs, proxies, and support/admin viewers.

Each worker can have a distinct resolver, network position, parser, credentials,
redirect policy, and request shape. Treat it as a distinct sink and use a fresh
controlled canary.

## Bounded inference and stop rule

Change one variable at a time. Never infer port state from a single timeout; use
repeatable controlled comparisons. Do not turn blind SSRF into broad port/subnet
enumeration. Once a distinct server-side fetch is proved, route filtering,
redirect, metadata, or request-shape questions to the matching reference pack.

## Sources

- PortSwigger, [Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- OWASP, [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
