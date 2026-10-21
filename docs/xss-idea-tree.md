# XSS Idea Tree — Advanced-XSS Intake and Agent Path

- **Status:** methodology note; active only when the reviewed commit is in the selected beta projection. Not a target finding or a payload pack.
- **Owner:** BBH `xss` and `xss-payload-engineering`; selected XSS lane owns proof.
- **Canonical path:** `docs/xss-idea-tree.md`.
- **Supersedes:** none; extends `docs/xss-mechanism-ideation.md`.
- **Implementation commits:** `a7e55310e7d9b81f7407fc0cef9f8632d3340be1`, `b09484a43ca4bac403a83f87a3ed75a28b48bf0b` (original tree); `5fd1ea9962d00e3ed353254c975c98593632d9dd` (creative-breadth correction). Confirm the selected beta/runtime revision separately.
- **Source snapshot:** Advanced-XSS README at `7d529fe86fe8bdef73b393db9274e427cf637182` (sanitized fetch, SHA-256 `0bbf3107451b73334bc95d589ab47ed12c1a4b194e155bc92fab77a754a96259`). This is inspiration, not evidence a modern browser executes every example.

## The tree agents follow

```text
xss (methodology, scope, evidence, proof)
├─ observed delivery: reflected-xss / stored-xss / dom-xss / blind-xss
│    └─ xss-lifecycle when the same value reaches a later consumer
└─ warm path or mapped sink with a missing next idea
     └─ xss-payload-engineering (capability profile + candidate queues)
          ├─ references/mechanism-ideation.md
          │    ├─ mXSS: same sanitized markup changes on real reparse
          │    ├─ post-check composition: application joins checked pieces
          │    ├─ URL check/use mismatch and other observed transforms
          │    └─ structural DOM influence
          ├─ references/parser-stage-character-variants.md
          │    └─ a real decode, normalization or charset stage
          └─ references/idea-tree.md (on demand; not an idea boundary)
               ├─ client-interpreters.md
               │    ├─ template compiler / Web Components / SVG or XML
               │    ├─ CSS-to-script / import maps / WASM / Service Workers
               │    └─ content sniffing / developer-only consumers
               ├─ derived-consumers.md
               │    ├─ prototype pollution → observed XSS gadget
               │    ├─ postMessage / GraphQL / SSE / WebSocket events
               │    └─ AI/Markdown output / delayed previews
               └─ defense-edges.md
                    ├─ sanitizer configuration / Trusted Types
                    ├─ CSP nonces, cache and actual script caller
                    └─ WAF/encoding/polyglot candidate → final browser proof
```

All leaf files above are **inside `skills/xss-payload-engineering/references/`**.
The root `xss` skill gained one conditional pointer, and payload engineering
one pointer; it does not inject all the leaves into every run. Agents still use
`dom-xss`, `xss-lifecycle`, `xss-waf-evasion`, and `xss-technology-research` as
owners when their triggers apply. A source, sink, unexplained transformation,
or research clue may open several leaves and inspire ideas outside this tree.
The agent retains materially distinct hypotheses in parallel; there is **no
number of ideas or leaves to exhaust**. A comparison, inert marker or predicted
observation can help assess a particular causal claim; it is not permission to
have that idea. A negative narrows only the tested edge. The selected lane owns
live testing and browser proof; its existing scope/rate/effects rules still
apply. The tree is neither an automatic payload sweep nor an exhaustive list.

## A concrete walk

Suppose a stored profile field reaches a component preview as safe text, but a
separate notification is observed to consume that field through a Web Component.
The agent uses `stored-xss` plus `xss-lifecycle` to link the writer and both
consumers; `dom-xss` traces the component's browser-side field-to-sink path.
It can start with `client-interpreters.md` for the component, keep the first
preview and other feeders open, and load `derived-consumers.md` if a message
handler also feeds it.
It traces a controlled marker through the component callback and can compare
a text-only path when interpreting a result; that comparison does not limit
candidate ideas. If the callback never parses the tested field as
HTML/URL/template or the notification is not reachable in an owned view, it
records that missing edge without closing other feeders or consumers. No “Web
Components bypass” is claimed. If a
specific framework/library becomes relevant, `xss-technology-research` checks
a bounded source/card.
The selected `stored-xss` delivery lane and `dom-xss` browser-processing lane
share the evidence packet; `attempt-recording-policy` owns the exact probe
writer, and browser proof and cleanup remain with the relevant XSS lanes.
The stored-field path, message-fed path and notification view remain separate
open ideas while one exact edge is tested. An inert result for the field does
not close the message or a newly noticed renderer; an idea outside these leaves
returns to the XSS exploratory queue. Live probes still follow the inherited
authorization and rate boundaries.

## Independent agent walk (read-only)

An independent agent began at `skills/xss/SKILL.md` and tried three synthetic
observations against the committed tree. Its verdict was **MINOR**, not a claim
of exploitability. A second technical reviewer judged the implementation
**ACCEPT for beta review**, with three documentation nits corrected below.

1. **Sanitized markup, but the panel is absent.** The delivery lane is unknown;
   do not invent reflected or stored provenance. Route to
   `mechanism-ideation.md`, first establish an owned mounted panel and a rendered
   inert marker, then compare a context-appropriate candidate with a
   text/one-pass rendering if it helps interpret that claim. If the panel stays
   absent, record the missing fixture; neither “sanitizer effective” nor “path
   exhausted” follows.
2. **Stored field in a mounted Web Component, with a message feeder.** Use
   `stored-xss` for the delivery, `dom-xss` for the component trace and
   `xss-lifecycle` for later consumers. Load `client-interpreters.md` for the
   callback/slot; load `derived-consumers.md` *only if* the message truly feeds
   it. Follow separate inert markers from stored field and message handler to
   an actual sink; a renamed-field/text-only control falsifies a claimed edge.
   A component or `postMessage` listener merely existing is insufficient.
3. **CSP nonce/CSS assertion plus an import-map writer.** Use `dom-xss` for
   module resolution and `client-interpreters.md` for the installed map; add
   `defense-edges.md` for the *delivered* CSP question. Check writer control,
   ordering, eligible not-yet-resolved specifier and actual module fetch with a
   fixed-map control. A map cannot change an already resolved specifier. A CSS
   selector seeing `script[nonce]` does not establish access to the nonce bytes;
   HTML attribute emptying depends on header-delivered CSP. Stop the XSS claim
   if the map is uncontrolled, the relevant specifier already resolved, or the
   module execution is blocked. CSS influence remains a separate observation.

The first agent liked **one root pointer → on-demand leaves**: it widened
investigative questions without a startup payload catalogue. Its initial
wording implied one leaf per idea; a later independent mentality review flagged
that as too narrow. Leaves now combine freely as relevant, and a mechanism
outside them returns to the XSS exploratory queue. The first agent also noted
blurred proof/Attempts ownership, clarified in the agent-facing references. The
technical reviewer also asked for the introductory mismatched-context heading
to be accounted for and the import-map/nonce caveats to be precise. No live
target requests or upstream payload execution were part of either review.

## Pinned upstream heading audit (coverage of ideas, not findings)

The README has **29 non-basic, non-duplicate technique headings** after excluding
its reflected/stored/DOM taxonomy and one repeated DOM-clobbering heading.
Every heading below has an explicit destination or exclusion. “Conditional”
means a *question* whose claimed execution still needs a reachable consumer;
contrasting observations help assess it but are not a gate on ideas. It does
**not** mean a working bypass. “Existing” means a prior BBH owner covered the
core question; new tree pointers make the owner discoverable. Categories
overlap in real paths.
The 29 headings measure source intake, **not the possible number of XSS ideas**;
an unlisted or newly observed mechanism remains eligible for exploration.
The count excludes the introductory **Context-Based XSS** subsections (HTML,
attribute, JavaScript, URL, DOM, and **Mismatched Contexts (2025/2026 Trend)**)
because they describe context fundamentals rather than headings in the selected
technique sections; the mismatched-context idea is still routed to
`mechanism-ideation.md` (post-check rewriting/changed consumer),
`xss-lifecycle` (later renderer), and `parser-stage-character-variants.md`
(observed decode/normalization). Exclusion from this denominator is not a claim
that it has no value or is unaddressed.

| Upstream heading | Route / disposition |
| --- | --- |
| Mutation XSS (mXSS) | Existing `mechanism-ideation.md`: same-markup reparse, not application joining. |
| Client-Side Template Injection | `client-interpreters.md`: prove runtime compile of controlled text, not ordinary template interpolation. |
| Using Encodings | Existing `parser-stage-character-variants.md`: observed decoder only. |
| URL Encoding Tricks | Existing `mechanism-ideation.md` + parser-stage reference: final writer/URL parser. |
| Hexadecimal Escaping | Existing parser-stage reference: only the acting JS/URL/HTML grammar. |
| Unicode Normalization Attacks | Existing parser-stage reference: prove NFKC/other actual stage. |
| Template Literal Injection | Existing payload selection + `client-interpreters.md`: identify a real JS/template compiler. |
| WAF Bypass Techniques (2025–2026 Updates) | Existing `waf`/`xss-waf-evasion`; `defense-edges.md` routes back to browser proof. |
| WebAssembly (WASM) XSS | `client-interpreters.md`: JS glue and controlled call/output; WASM alone is not DOM execution. |
| Service Worker XSS | `client-interpreters.md`: valid owned registration or message-to-render path; reject `data:` shortcut. |
| Import Maps Exploitation | `client-interpreters.md`: controlled map before actual module resolution and allowed module fetch. |
| CSS Injection to XSS | `client-interpreters.md`: observed CSS-to-executable-sink bridge; style/exfil alone is not XSS. |
| Trusted Types Bypass | Existing mechanism guide + `defense-edges.md`: policy output and caller control. |
| AI Agent Weaponization & Prompt-to-XSS | `derived-consumers.md`: controlled model output into executable renderer; prompt injection is separate. |
| Polymorphic & AI-Generated Payloads | Existing exploratory queue + `defense-edges.md`: candidate generator, not a new mechanism. |
| Sanitizer Bypass Techniques — DOMPurify & Sanitizer API | Existing mechanism guide + `defense-edges.md`: pin sanitizer/version/config and actual sink. |
| Advanced CSP Bypass — Nonce Leakage via CSS & Cache | `defense-edges.md`: HTML nonce hiding and observed cache/script caller; source claim is not universal. |
| postMessage Exploitation | Existing `dom-xss` + `derived-consumers.md`: origin/source, handler and executable sink. |
| Cross-Site WebSocket Hijacking (CSWSH) | **Out of XSS:** authentication/Origin class unless a separate controlled event reaches an executable renderer. |
| GraphQL Injection to XSS | `derived-consumers.md`: controlled error/path/extension into mounted UI. |
| Payload Fragmentation & Reassembly | Existing mechanism guide: post-check composition, not automatically mXSS. |
| Advanced DOM Clobbering | Existing mechanism guide: allowed name/id to observed JS property lookup. |
| Server-Sent Events (SSE) Injection | `derived-consumers.md`: writer → event → handler → render. |
| Console Injection & DevTools XSS | `client-interpreters.md`: distinguish owned dashboard renderer from social-engineered self-XSS. |
| XSS in SVGs | `client-interpreters.md`: namespace and inline/document/image consumer differ. |
| Prototype Pollution to XSS | `derived-consumers.md`: separate pollution writer and downstream gadget sink. |
| Web Components XSS | `client-interpreters.md`: controlled field through callback/slot to parser. |
| AI/ML Application XSS | `derived-consumers.md`: same model-output-to-renderer question; no duplicate card. |
| Content Sniffing | `client-interpreters.md`: delivered headers and actual victim browser document interpretation. |

**What remains deliberately unimported:** raw payload blocks, case studies as
portable target facts, JavaScript snippets requiring attacker JS already to run,
invalid/configuration-dependent examples, and non-XSS classes. A matched
library/version could justify a separately reviewed ResearchMap mechanism card;
it does not belong in a universal payload bank. This broadens the agent's
conditional *questions*, not the set of independently demonstrated bypasses.

Primary constraints checked for representative dubious examples: WHATWG nonce
attributes and import-map processing; W3C CSP Level 3; Service Worker
registration; WebAssembly JS interface. The source and exact reviewed commit
are noted above; target behavior must be observed afresh.
