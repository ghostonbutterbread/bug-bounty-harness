# Local Notes Map

Use these as local research anchors when applying `/request-exploration`. Do not treat old notes as current target permission; always inherit scope, ownership, and rate rules from `/live-testing-policy`.

## Strongest Existing Notes

- `/home/ryushe/my_bounty_notes/vulnerabilities/Logic vulns/Business logic vulns.md`
  - Unconventional input: different data types, high/low values, limits, transformations, and normalization.
  - Coupon and cart abuse: mass assignment, HTTP Parameter Pollution, server-side request tampering, negative delivery charges, and negative quantities.
  - Premium feature abuse: true/false access flags and Burp Match & Replace for feature-gating values.
  - Critical parameter manipulation: identify suspicious parameters, mutate name/value pairs, JSON, XML, and cookies.
  - Business-flow bypass: observe each workflow step through a proxy, then tamper with hidden or client-controlled business constraints.

- `/home/ryushe/notes/superdrug/ideas/reg-code-bypass.md`
  - Concrete request-exploration pattern: remove `regCode`, set it to empty, change it to nearby values, and compare price or booking behavior.

- `/home/ryushe/notes/superdrug/ideas/prescription-enumeration.md`
  - Parameter discovery pattern: enumerate product parameters, then check price/stock manipulation through parameter tampering.

- `/home/ryushe/my_bounty_notes/Web Testing/graphql/enumerating.md`
  - Content-type differential pattern: GraphQL should normally use POST with `application/json`; test whether alternate methods or `x-www-form-urlencoded` are accepted.

- `/home/ryushe/my_bounty_notes/tools/ffuf.md`
  - Fuzzing support notes: status-code filtering, proxying through Burp, request-proto, and controlled-rate endpoint discovery.

- `/home/ryushe/notes/appsec/ghost-field-notes/2026-05-25-pfp-common-vulns.md`
  - Request primitive mapping: upload/import/crop/render/storage/delete/update endpoints, replay/order behavior, parser/transcoder clues, and owned-account ID mutation.

## Twitter/X Notes Search Result

No strong local Twitter/X capture was found for generic request mutation. The closest local material is older bounty-note content and linked writeups/videos rather than saved posts.
