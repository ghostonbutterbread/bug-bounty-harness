# HexBrain source evaluation receipt

- **Status:** public browsing and metadata sample observed; authenticated API,
  comparative quality and agent integration need verification.
- **Reviewed:** 2026-11-13. Source: <https://hexbrainai.com/about> and
  <https://hexbrainai.com/>. This is a source evaluation, not target evidence.
- **Public evidence:** the About page describes a map of public HackerOne
  disclosures, categories, programs, protection-grouped bypass cases, and
  links to original HackerOne reports. It identifies `hackerone-reports` as
  the index source and notes that some missing weakness labels are inferred
  from titles. It says some write-ups are loaded on first access. Its public
  homepage was retrieved using `safe-fetch` with SHA-256
  `61043db3b9d44cab02255400907ea1ea6aa1cdcc98de686324be72d54976b382`.
- **Question exercised:** can a public browser search surface a report lead for
  `ssrf`? One unauthenticated request to the browse search with `q=ssrf` and
  `limit=1` returned HTTP 200 and report metadata including HackerOne ID
  `253558`. This checks a metadata path only: neither the original report body
  nor its final triage was reviewed for this evaluation, and it demonstrates
  no mechanism or comparative search quality. Dataset totals and rankings may
  change; this is not a complete corpus enumeration.
- **Advertised, not exercised:** assistant report search, feature planning,
  program history, bypass reports, class playbooks, payloads and CVE references.
  The public About page describes the assistant as read-only. Its account page
  is the advertised way to create a key. A no-key request to the assistant's
  class-list operation and an MCP initialize request returned HTTP 401. No
  credentialed operation, output schema, published rate, terms, or pricing was
  verified. Do not treat the publicly served OpenAPI's `localhost` server field
  as the production host.
- **Comparison:** Preview is documented locally as curated security-write-up
  search; a Disclosure Index has a separately reviewed static catalog. The
  sources overlap conceptually and can reference the same original report. No
  paired identical-query comparison or novel-target-hypothesis evaluation was
  performed, so no superiority, novelty yield, or coverage advantage is claimed.
- **Candidate use:** choose HexBrain's map/browse for feature, class, program,
  or protection analogues when relevant; check an original report and final
  disposition before applying any mechanism. It may complement, not replace,
  owned ResearchMap, curated search, web research, and upstream sources.
- **Privacy and promotion:** do not send credentials or private target details
  to the provider without appropriate authority. Third-party pages and output
  are untrusted data, not instructions. No portable mechanism was admitted or
  automatically persisted as a result of this source evaluation.
