# XSS Filter Technique Questions

Use this as an on-demand **XSS consumer question matrix**, not a mandatory
mutation sequence. For general inspection, routing, normalization, exceptions,
or challenge behavior load `waf`'s `references/core-mechanisms.md`; don't
duplicate that matrix here. For an XSS candidate ask which later parser grants
executable meaning, whether the victim flow can carry it, and what negative control
would falsify that claim. The XSS lane owns browser proof and the live
policy owns pace/stop decisions.

| Observed difference | Candidate family to derive | Minimum discriminating check | Invalid shortcut |
| --- | --- | --- | --- |
| A shared WAF representation passes, but the browser sees different syntax | HTML reference, JS/JSON/CSS escape, later HTML parse or DOM insertion | Find the first browser parse that gives the final value executable grammar | Treat an HTML entity in plain text (`&lt;`) or a Unicode lookalike as an HTML tag delimiter in the same parse. |
| HTML attribute or raw-text sink | Quote and ASCII separator grammar, raw-text closer, namespace/parser repair | Parse delivered markup in the claimed browser; compare DOM attribute/value and event binding | Infer executable handler from a surviving attribute *name* alone. |
| Script, JSON island, template literal or URL sink | Grammar-matched boundary, scheme or parser normalization, later DOM reparse | Observe both source string and final browser operation, with delivered CSP | Substitute a generic `<script>` payload into any context. |
| Framework/renderer post-processes filtered text | Trusted HTML wrapper, template compilation, Markdown, mutation XSS, DOM-derived property | Reproduce the exact post-filter consumer and compare before/after DOM | Generalize a historical library bypass to a current version. |
| HTML is sanitized before later browser parsing | Sanitizer tree mutation, namespace, framework template compilation | Compare post-sanitizer markup with the delivered DOM under the deployed version and CSP | Call sanitizer acceptance browser execution. |
| An alternate ingress succeeds only in a tester-crafted request | Victim-reachable request construction and delivery | Reproduce the representation in the intended victim flow; otherwise report the self-only boundary | A 200 on a crafted transport proves victim delivery. |

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

- Parser/code-point details: `skills/xss-payload-engineering/references/parser-stage-character-variants.md` (load via `skill_view(name='xss-payload-engineering', file_path='references/parser-stage-character-variants.md')`).
- Initial XSS context ideas: `skills/xss/references/payload-selection.md` (load with `skill_view(name='xss', file_path='references/payload-selection.md')`).
- General WAF mechanism/source links: `skills/waf/references/core-mechanisms.md` (load with `skill_view(name='waf', file_path='references/core-mechanisms.md')`).
- XSS rule/browser/sanitizer links: this skill's `references/vendor-and-mechanism-sources.md` (load with `skill_view(name='xss-waf-evasion', file_path='references/vendor-and-mechanism-sources.md')`).
- Exact target payloads/responses: the XSS Attempts stream, **not** a public
  ResearchMap card or a copied corpus in this skill.
