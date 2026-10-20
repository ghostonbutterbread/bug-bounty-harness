# XSS Mechanism Ideation at Parser and Sanitizer Boundaries

Load on demand from `xss-payload-engineering` after a concrete source, render
context, transform, or plausible sink is observed. This is a **reasoning aid**,
not a payload menu or a new proof standard. `xss` and its selected lane retain
scope, browser proof, ownership, and closure. Read
`parser-stage-character-variants.md` for representation specifics; use
`xss-technology-research` / ResearchMap for an observed library/configuration.

## The next-idea worksheet

Write this in a few lines, not a new ledger:

```text
Controlled source(s) / ownership:
First observed blocker and exact input/output:
Final consumer / grammar / delivered CSP:
Intervening stages: decode → validate → sanitize → concatenate → serialize → reparse
Which stages were observed vs inferred; does the consumer actually mount?
Surviving primitives and unavailable primitives:
Candidate mechanism, alternate explanation, smallest discriminator:
```

Work **backward** from the browser-interpreted consumer. Before interpreting a
non-firing candidate as a sanitizer negative, establish the positive reachability
chain: source accepted → value stored or reflected → relevant consumer mounts →
inert marker appears there. Sink-first reasoning can proceed while a source is
still being found; label the missing link rather than inventing its execution.
Then compare candidate representation before and after the *acting* layer,
resulting DOM or navigation, and browser execution under delivered CSP. A
missing consumer or owned fixture is not a sanitizer negative. A blocked input
is not a browser negative. When no feasible final interpreter or
attacker-controlled source exists, record the missing edge instead of
manufacturing variants.

## Branch on the observed boundary

| Signal | Mechanism question and minimal distinction | Falsifier or next branch |
| --- | --- | --- |
| HTML sanitizer removes hazardous elements/attributes | Does the actual output, after a **later** DOM serialization, concatenation, or HTML insertion, form a different tree? Compare sanitized string or node, `outerHTML`/`innerHTML` after the second parse, and a safe one-pass control. Inspect parser namespace, raw-text/comment context and exact sanitizer config. | Same safe tree after all real parses, or no reparse in this consumer → do **not** call it mXSS. Look at another owned consumer or stop this mechanism. |
| Separate fields or fragments pass checks | Are two controlled values assembled **after** validation/sanitization and then interpreted as HTML, URL, template, or code? Compare isolated A/B controls, joined result, and safe text-only assembly. | Assembly happens before the sanitizer, or output uses `textContent` → no demonstrated split-payload bypass. A WAF seeing separate request fields is not proof the browser assembles them. |
| URL attribute keeps a web link but rejects `javascript:` | Identify the exact writer, validator and parser used at each stage. Compare inert schemes/whitespace, protocol-relative and URL-component controls against the final browser-resolved `href`/navigation on the *same* route. Explore a different writer or downstream URL construction only if observed. | Backend rejects the variant before storage, or browser resolves it to a benign URL; a timeout/no popup is not click/execution proof. A percent-encoded scheme is not magical: name the decoder that runs **after** validation. |
| HTML is escaped in one view | Is that escaping specific to one serializer/consumer? Trace the same controlled value to a separately observed preview, notification, export, or client renderer; classify its context afresh. | Same escaped text in the only reachable owned view → record exact negative, not a general XSS clearance. |
| Trusted Types or CSP blocks execution | Which precise sink/policy created TrustedHTML, and what does the *delivered* CSP permit? Locate a caller-controlled argument to an existing trusted policy or an actually allowed execution route. | No attacker control over trusted caller/output, or enforced CSP blocks the claimed path. Never infer a bypass from a Report-Only violation, a permissive default policy, or raw markup alone. |
| Sanitized markup can influence DOM structure | Does allowed `id`/`name`, form, or other structural markup collide with an **observed** global/property lookup or select a URL/config that a trusted script later consumes? Compare named versus renamed control and the actual JavaScript call site. | No attacker-controlled markup at that lookup or typed/config access prevents the collision. DOM clobbering is not the same as executing markup. |
| Asynchronous or derived content appears | Track provenance through Markdown/AI output, GraphQL error, `postMessage`, SSE or WebSocket event to the exact render function. Compare event body and safe `textContent` renderer with any HTML insertion. | Merely reaching an API, stream, or model is not XSS; no controlled event-to-sink path means a source or consumer is missing. Prompt injection and WebSocket auth bugs are separate classes. |

These are **questions**, not instructions to run every family. If a configuration
or source trace disproves a presumed reparse stage, retire that branch and keep
the observation; do not respond with a larger mXSS list. At an unexplained
boundary, select one non-equivalent mechanism and its safe control; after an
inert matrix, prioritize a newly observed stage, writer or consumer over another
syntax permutation of the same failed stage. Consult `xss-lifecycle` when the
value changes consumers and `waf-live-policy` when the first blocker is at the
edge. Do not probe non-owned staff/public consumers merely to complete a chain.

## Terms that must not be conflated

**Mutation XSS (mXSS):** parsed/sanitized markup changes structure or meaning
when the browser serializes/reparses it, or when a sanitizer and later consumer
interpret the tree differently. It requires a real parse-stage transition and
an unsafe result, not merely two stripped tags. HTML namespaces and comment or
raw-text boundaries can matter, but a known historical vector is not evidence
that a current sanitizer version is vulnerable.

**Fragmentation/reassembly:** independently controlled parts become meaningful
only after composition at a later sink. This can be an application design error
without any browser parser mutation. Show where the join occurs relative to the
security check.

**Double decode / entity / Unicode:** representation changes only if an actual
stage decodes or normalizes before the interpreter. An HTML character reference
in text does not retroactively become HTML syntax without a subsequent reparse;
fullwidth punctuation is not an HTML delimiter without a separate normalization.

**Sanitizer output vs safe use:** a sanitizer may correctly clean its input for
one HTML insertion yet be followed by application code that modifies or
reinterprets the output. That is a composition failure, not automatically a
library vulnerability. Pin library version, options, parser and browser when a
library-specific claim is relevant.

## Walkthrough (hypothetical, not a target result)

Suppose fields `prefix` and `suffix` are accepted individually, then the UI
builds `preview.innerHTML = clean(prefix) + clean(suffix)`. First confirm both
markers appear in that exact preview, and record each `clean(...)` output.
Compare (1) A alone, (2) B alone, (3) the joined value, and (4) the same joined
value assigned via `textContent` or sanitized *after* joining. If the pieces
are individually inert but the joined markup creates an executable consumer,
**post-sanitization composition** is the mechanism. If no join occurs, the
preview is gated, or the final tree remains inert, do not label it a bypass.
This is fragmentation; mXSS would instead need a demonstrated tree mutation
across parser stages. A local fixture can teach that contrast but never proves
an unrelated app is affected.

## Research and provenance

The Advanced-XSS collection inspired these prompts, not a universal payload
catalog. Cross-check concrete claims against the implementation or a primary
browser/sanitizer research source. For a matching application fingerprint,
query bounded ResearchMap using `library/config + exact transition + sink` and
review the card's prerequisites and status before adapting it. Keep portable
cards in ResearchMap, target facts in MapStore, untested run hypotheses in the
Hypothesis Ledger, and exact controlled probes in canonical Attempts. A card's
local reproduction is not target proof.

Sources for the narrow parser/composition principles:
- DOMPurify README, “Is there any foot-gun potential?” (post-sanitize
  modification): https://github.com/cure53/DOMPurify
- Gareth Heyes, “Bypassing DOMPurify again with mutation XSS” (historical,
  browser-/version-specific example; patched in DOMPurify 2.1):
  https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
- WHATWG HTML parsing and character-reference rules:
  https://html.spec.whatwg.org/multipage/parsing.html
- WHATWG URL parsing and input preprocessing:
  https://url.spec.whatwg.org/
- User-submitted inspiration, Advanced-XSS README, reviewed for mechanisms not
  copied as tested payloads: https://github.com/Karthikdude/Advanced-XSS
