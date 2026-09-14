# SSRF Idea Seeds

Use these as "how to look" seeds after a fetch surface exists. They are not
rules or permission to exceed scope. For the maintained detailed catalog, load
`technique-packs/baseline-fetch.md`, `technique-packs/parser-redirect.md`, or
`technique-packs/metadata-scheme.md` based on the observed boundary.

## Core Concepts

- web application security
- server-side request forgery
- input validation security
- URL parsing exploits
- filter bypass
- security filter evasion techniques
- web application firewalls
- network segmentation for security

## Fetch Behavior

- direct server-side HTTP fetch
- blind server-side fetch
- reflected fetched body
- reflected status code
- reflected response headers
- asynchronous fetch after workflow completion
- redirect-following behavior
- server-side browser rendering
- proxy/cache fetch behavior
- DNS resolution timing

## URL Parser Confusion

- userinfo host confusion
- trailing dot hostname
- mixed case scheme
- encoded dots
- encoded slashes
- backslash vs slash
- fragment stripping
- query/path host confusion
- absolute URL inside path
- scheme-relative URLs
- parser differential: validator vs fetch library
- browser URL parser vs backend URL parser

## IP Address Obfuscation

- decimal IPv4
- octal IPv4
- hexadecimal IPv4
- shortened IPv4
- mixed-radix IPv4
- IPv6 loopback
- IPv4-mapped IPv6
- localhost aliases
- 0.0.0.0 behavior
- link-local addresses
- RFC1918 ranges
- encoded IP components

## DNS And Redirects

- DNS rebinding
- fast DNS changes
- owned hostname with stable A/AAAA record resolving to an internal IP
- hostname-only allowlist versus resolved-address validation gap
- validation-time DNS versus connection-time resolution behavior (not DNS rebinding)
- CNAME chains
- open redirect to internal target
- same-site redirect chain
- redirect validation before follow
- redirect validation after follow
- protocol downgrade/upgrade redirects
- redirect through allowed CDN/storage domain

## Metadata And Internal Targets

- AWS metadata root
- GCP metadata root
- Azure metadata root
- ECS task credentials root
- Kubernetes service IPs
- Docker API socket/proxy hints
- Redis/Elasticsearch/admin banners
- loopback service banners
- internal admin panels
- cloud metadata required headers

## Header And Proxy Ideas

- HTTP header injection
- `Host` confusion
- `X-Forwarded-Host`
- `X-Forwarded-For`
- `Forwarded`
- metadata headers
- proxy authentication headers
- hop-by-hop headers
- request smuggling adjacency
- internal routing headers

## Scheme And Content Ideas

- `http`
- `https`
- `file`
- `gopher`
- `dict`
- `ftp`
- `data`
- `jar`
- SVG external references
- XML external entities
- HTML base tag effects
- MIME sniffing changes

## Safe Proof Ideas

- controlled callback hit
- status-only internal root
- banner-only internal service proof
- metadata root key names without secret values
- timing tied to a specific controlled destination
- redirect trace evidence
- error message showing server-side resolver behavior
