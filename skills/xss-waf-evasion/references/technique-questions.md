# XSS Filter Technique Questions

Use this as an on-demand **question matrix**, not a mandatory mutation sequence.
For each candidate, state: (1) what the control inspects; (2) what representation
survives; (3) which subsequent parser gives it executable meaning; (4) whether
the actual victim flow can carry it; (5) one negative control. The XSS lane
owns the browser proof and the live-testing policy owns pace/stop decisions.

| Observed difference | Candidate family to derive | Minimum discriminating check | Invalid shortcut |
| --- | --- | --- | --- |
| Edge sees a body representation, origin accepts another | Declared charset, body parser, BOM, JSON/form/multipart component | Hold semantic input constant; compare control result and exact origin value under each accepted transport | A 200 on a crafted transport proves victim delivery. |
| WAF and app select different request pieces | Field/component coverage, duplicate key, nested shape, method/content type | Inert markers identify which value each stage uses and whether the route accepts it | Assume a branded WAF scanned every request field. |
| Different decode orders | Percent, HTML reference, JS/JSON/CSS escapes, Unicode normalization | Find first stage where forms converge; inspect eventual syntax, not appearance | Treat an HTML entity in plain text (`&lt;`) or a Unicode lookalike as an HTML tag delimiter in the same parse. |
| HTML attribute or raw-text sink | Quote and ASCII separator grammar, raw-text closer, namespace/parser repair | Parse delivered markup in the claimed browser; compare DOM attribute/value and event binding | Infer executable handler from a surviving attribute *name* alone. |
| Script, JSON island, template literal or URL sink | Grammar-matched boundary, scheme or parser normalization, later DOM reparse | Observe both source string and final browser operation, with delivered CSP | Substitute a generic `<script>` payload into any context. |
| Framework/renderer post-processes filtered text | Trusted HTML wrapper, template compilation, Markdown, mutation XSS, DOM-derived property | Reproduce the exact post-filter consumer and compare before/after DOM | Generalize a historical library bypass to a current version. |
| Response rewritten after request inspection | Formatter, CDN transformation, serializer, second HTML parse | Compare WAF-inspected request, response bytes, and browser DOM | Call any output mutation a WAF bypass. |
| Same input behaves differently over time/client | Rate/bot/challenge/session or scope-specific rule | Preserve a green control and legitimate session; classify policy outcome | Rotate identities or IPs to sustain an automated bypass loop. |

A reject-on-match application filter and a sanitizer that rewrites output are
separate branches. If the former and the final consumer see the same decoded
value and grammar, do not keep renaming equivalent strings; investigate a new
route, parameter exclusion, later consumer, or parser stage only when evidence
suggests one. If the source is DOM-only and the WAF never sees it, return to
`dom-xss` rather than trying edge encodings.

## Worked reasoning pattern (abstract, not a reusable payload)

A controlled JSON value blocks in one byte encoding but an accepted alternate
transport reaches the origin unchanged. This supports an **inspection-versus-
origin decoding** hypothesis. Before constructing XSS syntax, establish (a)
that the selected JSON field reaches an HTML-parsing or script consumer and
(b) that a victim-reachable caller can send the alternate transport. If only a
tester-crafted request can do so, the result may prove a filter differential and
self-only execution without proving victim delivery. Keep these claims apart.

## Source ownership

- Parser/code-point details: `xss-payload-engineering/references/parser-stage-character-variants.md`.
- Initial XSS context ideas: `xss/references/payload-selection.md`.
- Vendor and primary mechanism links: `references/vendor-and-mechanism-sources.md` in this skill.
- Exact target payloads/responses: the XSS Attempts stream, **not** a public
  ResearchMap card or a copied corpus in this skill.
