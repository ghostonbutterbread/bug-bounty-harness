# XSS Idea Tree — Choose a Consumer, Then a Branch

Load **on demand**, after `xss` and the observed reflected/stored/DOM/blind lane.
This is a navigation aid for a warm path or a concrete source/sink question, not
an instruction to test every leaf. The selected lane retains authorization,
execution proof, cleanup and closure; `attempt-recording-policy` owns the exact
per-probe writer, and `xss-lifecycle` owns later-consumer lineage.

```text
controlled source OR plausible consumer OR unexpected transform/clue
  └─ trace possible feeders/interpreters; check reachability to interpret results
       ├─ value changed across check/parse? → mechanism-ideation.md
       │    └─ actual decode/normalization? → parser-stage-character-variants.md
       ├─ client interprets text/config/media? → client-interpreters.md
       ├─ message, derived data or model output? → derived-consumers.md
       ├─ CSP/Trusted Types/sanitizer/filter is the acting control? → defense-edges.md
       ├─ unlisted/surprising mechanism? → owning XSS lane + exploratory queue
       └─ no controlled source, reachable consumer or owned fixture?
            → retain the idea with its missing link; do not claim a bypass
```

| Observed signal | Useful starting leaf and question (not an exclusive route) |
| --- | --- |
| Sanitized markup, separately checked fields, URL validator, DOM structure, later HTML parse | `references/mechanism-ideation.md`: which **observed** transform changes the interpreter's input? Keep mXSS separate from application concatenation. |
| Encoding, case, Unicode, entity, charset or double-decode claim | `references/parser-stage-character-variants.md`: which real decoder/normalizer runs before the final grammar? |
| Client template compiler, custom element, SVG/XML, CSS-to-script, import map, worker, WASM, MIME-sniffed document or developer-only view | `references/client-interpreters.md`: what component actually evaluates the controlled value and how does a victim reach it? |
| `postMessage`, event stream, GraphQL error, AI/Markdown output, prototype-sensitive object or later export | `references/derived-consumers.md`: trace controlled field → handler/transform → render sink; don't mistake an upstream API or model for execution. |
| CSP, nonce/cache, Trusted Types, sanitizer configuration, WAF or polymorphic candidate | `references/defense-edges.md`: locate the delivered/acting policy and distinguish a changed representation from an executable browser result. |

These file names are **skill-local** under `skills/xss-payload-engineering/`;
use `skill_view(name='xss-payload-engineering', file_path='references/<leaf>.md')`
when a leaf helps. Retain several materially distinct explanations of the same
observation; explore leaves together or in any order as clues warrant. The
tree's headings are not a checklist, idea quota, or boundary around new
mechanisms. An inert comparison narrows only the tested edge, not sibling
feeders, consumers, or untried interpretations. For an unlisted mechanism or
unexpected result, return to the selected XSS lane and its exploratory queue;
record missing links rather than inventing execution. Prioritize live probes by
information gain and inherited testing limits, not by leaf count.
`xss-technology-research` retrieves a bounded card for an observed
library/configuration; reusable source claims go to ResearchMap, target facts
to MapStore, and exact probes to canonical Attempts.

The upstream Advanced-XSS README inspired the *questions*, not the payloads.
Its headings include duplicates, pre-existing BBH coverage, configuration-only
claims and non-XSS classes. See `docs/xss-idea-tree.md` for the pinned-source
intake audit, excluded examples, and a human-readable full tree. A research lead
is not a validated bypass on this or any target.
