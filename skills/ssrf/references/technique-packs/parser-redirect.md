# Parser, Address, DNS, and Redirect Boundaries

Use when hostname/IP filtering, URL parsing, allowlists, or redirect handling
block an obvious internal URL. These are **representation families**, not
universal payloads: acceptance depends on the exact validator, parser, resolver,
and HTTP client. Preserve raw input and normalized/connected destination.

## Address representation families

Test one controlled baseline per class:

- dotted IPv4, shortened forms, 32-bit integer, hexadecimal, octal, and
  mixed-radix forms where the client runtime accepts them;
- IPv6 loopback/unspecified, IPv4-mapped/compatible, compressed/expanded forms,
  brackets, and a zone ID only with a documented platform differential;
- encoded host components, encoded/double-encoded dots or digits, and decoding
  order; and
- DNS aliases/wildcard names, trailing-dot FQDN, case, CNAME chain, IDNA/punycode
  and Unicode full-stop variants.

Cover address classes weak filters omit: unspecified, loopback, link-local,
private, carrier-grade NAT, multicast/reserved, IPv6 ULA/link-local, and cloud
metadata. Never infer equivalence from spelling: compare observed DNS/callback/
connection behavior.

## Authority and normalization differentials

Probe one boundary at a time:

- userinfo/repeated or encoded `@`; fragment/query placement;
- whitespace/C0 controls; slash/backslash/encoded-slash differences;
- missing slash after scheme, scheme-relative or extra-slash URLs, and absolute
  URL text in paths/queries;
- colon/port ambiguity, invalid/overflow port parsing;
- percent-decoding and double-decoding timing;
- Unicode/IDNA/full-width/control characters only in a lab or when evidence
  supports a parser differential; and
- IPv6 bracket, zone-ID, and serialization differences.

The hypothesis is a differential: validator A classifies one host while fetcher
B connects to another. Acceptance alone is not a bypass.

## DNS TOCTOU and rebinding

Determine whether validation and fetch perform independent resolution; record A
and AAAA answers, caches/TTL, redirect-time resolution, proxy resolution, and
retries. Test stable controlled aliases/CNAMEs first. Relevant gaps include
IPv4-only validation followed by an AAAA connection, checking only one answer,
and hostname allowlisting without post-resolution address checks.

DNS rebinding deliberately races validation to connection and requires explicit
approval plus controlled infrastructure. Do not use public rebinding services
against a live target without authorization. For the mechanism, rbndr.us
hostname format, and test flow, see `references/technique-packs/dns-rebinding.md`.

## Redirect classification

Record each hop, not only the initial URL: controlled/in-scope open redirect,
status code, relative/protocol-relative/encoded `Location`, scheme and port
change, loop/max-hop behavior, meta-refresh or `Refresh` behavior for renderers,
and whether method/body/cookies/auth survive. A redirect matters only when the
server followed it. Determine whether filtering occurs on the initial URL, every
hop, or final destination.

## Evidence and stop rule

Keep a public controlled baseline, rejected direct internal baseline, and a
single changed mutation. A callback, redirect trace, resolver trace, or distinct
response is evidence; a generic error is not. Stop a family when representative
variants normalize identically.

## Sources

- OWASP, [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- Orange Tsai, [A New Era of SSRF](https://owasp.org/www-project-cheat-sheets/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf)
- PortSwigger, [SSRF](https://portswigger.net/web-security/ssrf)
- HackerOne, [curl IPv6 zone-identifier parser discrepancy](https://hackerone.com/reports/2814750)
- PayloadsAllTheThings, [SSRF collection](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Request%20Forgery/)
