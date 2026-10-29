# Subdomain probe redirect observations

The subdomain agent's HTTP probe records a 3xx status without following it. A
present Location is represented as `[redacted]` in `redirect_url`; an absent
Location is an empty string. Redirect bodies and titles are not collected.
`content_length` is zero for these responses, not the size of the remote body.
Other successful responses retain their normal title and content length.

## Deferred redirect discovery

This intentionally loses destination and final-page discovery that previously
came from automatically following redirects. Restoring it requires a separate,
explicitly authorized design that validates each redirect hop against current
scope and handles sensitive destination data safely; the redacted observation
is not enough to reconstruct a destination. No such discovery is provided here.

This change only addresses the subdomain probe's redirect output. It is not a
general sanitizer for non-3xx content, inputs, other collection stages, or
network egress. Passive providers, local tools, and the independent takeover
checker retain their existing behavior and authorization requirements.
