# Subdomain probe redirect observations

The subdomain agent's HTTP probe records a 3xx status without following it. A
present Location is represented as `[redacted]` in `redirect_url`; an absent
Location is an empty string. Redirect bodies and titles are not collected.
`content_length` is zero for these responses, not the size of the remote body.
Other successful responses retain their normal title and content length.

## Helper contract

`probe_subdomain` requires an HTTPX client with `_capture_probe_response` as
its first response hook. It validates this before each request and rejects a
plain or incorrectly ordered client without sending; it does not install or
mutate hooks. The caller must not mutate hooks while requests are in flight.
`probe_all` creates and owns a correctly configured client. The response hook
uses request-local state, so concurrent probes do not share captures.

## Deferred redirect and takeover coverage

The probe does not inspect or retain destinations, so a 302 leading to a 404
cannot become takeover-eligible. The takeover recheck also does not follow
redirects, including when the server changes between the probe and recheck.
Direct eligible 403/404 rechecks and fingerprint matching remain in place;
previously followed recheck destinations are no longer checked.

The CLI reports partial coverage and `summary.json` records
`takeover_coverage.status` (`partial`, `skipped`, or `unknown` during the
intermediate output). `redirect_deferred_subdomains` lists observed redirects
from probing and rechecking; `failed_subdomains` lists recheck errors without
exception text. A malformed recheck Location can appear as a failure rather
than a known redirect because HTTPX may raise while parsing it. Partial is not
a claim that all other hosts were checked: the existing orchestrator only
rechecks selected dead statuses and excludes 200 and no-response results.
Skip-probe and skip-takeover modes do not provide takeover coverage.

**Wake condition:** implement and independently test an explicitly authorized,
bounded, manual per-hop traversal that validates each resolved destination
against the actual program scope *before* issuing a request. The current scope
validator's lexical checks do not model routing or DNS; `is_safe_url` does not
resolve hostnames. Substantiation must cover host/port/path exclusions, parser
ambiguity, relative locations, private/reserved DNS answers, DNS rebinding and
actual connection binding (including proxies), redirect limits, and safe
handling of destination secrets. Until then no redirect traversal is provided,
and the redacted probe observation cannot reconstruct a destination.

This change only addresses the subdomain probe and takeover redirect behavior.
It is not a general sanitizer for non-3xx content, inputs, other collection
stages, or network egress. Passive providers and local tools retain their
existing behavior and authorization requirements.
