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

`summary.json` retains `takeover_coverage` and its existing lists. Status is
`skipped` when takeover is disabled, `no-eligible` when nothing was eligible,
`complete` when all eligible direct rechecks finished without failure or
redirect, and `partial` for deferred redirects, probe/recheck failures, or
skipped probing of nonempty input, including scope-skipped probes. The intermediate
output is `unknown`.
`checked_count`, `deferred_count`, `skipped_count`, `failed_count` and their
corresponding subdomain lists classify results: checked means a completed direct
403/404 recheck, deferred means an observed redirect, failed includes status-zero
probe failures and failed/unexpected-status rechecks, and skipped includes
noneligible statuses and intentionally skipped operations. In particular,
`complete` is only complete for eligible direct rechecks, not all discovered
hosts; 200 and other noneligible statuses are not checked. A malformed recheck
Location can appear as a failure because HTTPX may raise while parsing it.
No exception text or redirect destination is included in coverage. Takeover
progress reports completed attempts separately from successful checks, deferred
redirects and failures; probe progress similarly separates attempts, responses,
failures and scope skips.

For compatibility, `scan_results.json` and `dead_subs.txt` still contain skipped
probe stubs, and `dead` still counts them along with other non-alive records.
`total_probed` now counts only records whose source is not `skipped`: it includes
attempts that received no response, but excludes both `--skip-probe` stubs and
scope-skipped probes. Consequently `alive` + `dead` can exceed `total_probed`;
consumers should inspect each record's `source` rather than infer attempts from
`dead` or the result-list length. The `total_probed` key remains unchanged, but
its corrected value differs from earlier summaries when stubs were present.

## Provider names and scope

Provider hostname fields are converted using IDNA and validated as hostnames
before exact/subdomain boundary matching; paths, queries, userinfo, ports,
controls and malformed labels are rejected without echoing the input. Wayback
and URLScan URL fields use the URL host, not a suffix-shaped substring. URLScan
accepts case-insensitive HTTP(S) schemes and IDNA hostnames, with an optional
valid numeric port. It rejects userinfo, controls, backslashes, percent-encoded
or ambiguous authorities, and malformed ports before canonicalizing the host;
paths and queries do not contribute to host matching. The
aggregate and prober validate again, including after the optional deduper.
When scope exists, exclusions are checked even without allow entries; when allow
entries exist, each probe URL must match them. HTTPS-to-HTTP fallback checks
scope for each scheme. Local JS fetches also check scope and do not follow
redirects. These are lexical checks, not DNS, proxy or connection containment;
name resolution, rebinding, actual connection destinations and provider API
redirect behavior are outside this change.

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
