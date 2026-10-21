# XSS Idea Tree — Advanced-XSS Intake and Agent Path

- **Status:** methodology note; active only when the reviewed commit is in the selected beta projection. Not a target finding or a payload pack.
- **Owner:** BBH `xss` and `xss-payload-engineering`; selected XSS lane owns proof.
- **Canonical path:** `docs/xss-idea-tree.md`.
- **Supersedes:** none; extends `docs/xss-mechanism-ideation.md`.
- **Implementation commit:** pending feature commit and independent review.
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
          └─ references/idea-tree.md (load only after a matching signal)
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
owners when their triggers apply. Before opening a leaf, the agent must observe
a source/sink, a mounted consumer or a concrete missing edge. After opening it,
the agent chooses one hypothesis, safe control and falsifier, then returns to
the selected lane for browser evidence. No corpus-size quota or payload sweep.

## A concrete walk

Suppose a stored profile field reaches a component preview as safe text, but a
separate notification is observed to consume that field through a Web Component.
The agent uses `stored-xss` plus `xss-lifecycle` to link the writer and both
consumers, then loads `client-interpreters.md` **only** for the component path.
It traces a controlled inert marker through the component callback and compares
a text-only control before selecting a candidate. If the callback never parses
the field as HTML/URL/template or the notification is not reachable in an owned
view, it records that falsifier; no “Web Components bypass” is claimed. If a
specific framework/library becomes relevant, `xss-technology-research` checks
a bounded source/card. Real browser proof and cleanup stay with `stored-xss`.

## Pinned upstream heading audit (coverage of ideas, not findings)

The README has **29 non-basic, non-duplicate technique headings** after excluding
its reflected/stored/DOM taxonomy and one repeated DOM-clobbering heading.
Every heading below has an explicit destination or exclusion. “Conditional”
means a *question* with a precondition and negative control, **not** a working
bypass. “Existing” means a prior BBH owner already covered the core question;
new tree pointers make the owner discoverable. Categories overlap in real paths.

| Upstream heading | Route / disposition |
| --- | --- |
| Mutation XSS (mXSS) | Existing `mechanism-ideation.md`: same-markup reparse, not application joining. |
| Client-Side Template Injection | `client-interpreters.md`: prove runtime compile of controlled text, not ordinary template interpolation. |
| Using Encodings | Existing `parser-stage-character-variants.md`: observed decoder only. |
| URL Encoding Tricks | Existing `mechanism-ideation.md` + parser-stage reference: final writer/URL parser. |
| Hexadecimal Escaping | Existing parser-stage reference: only the acting JS/URL/HTML grammar. |
| Unicode Normalization Attacks | Existing parser-stage reference: prove NFKC/other actual stage. |
| Template Literal Injection | Existing payload selection + `client-interpreters.md`: identify a real JS/template compiler. |
| WAF Bypass Techniques | Existing `waf`/`xss-waf-evasion`; `defense-edges.md` routes back to browser proof. |
| WebAssembly (WASM) XSS | `client-interpreters.md`: JS glue and controlled call/output; WASM alone is not DOM execution. |
| Service Worker XSS | `client-interpreters.md`: valid owned registration or message-to-render path; reject `data:` shortcut. |
| Import Maps Exploitation | `client-interpreters.md`: controlled map before actual module resolution and allowed module fetch. |
| CSS Injection to XSS | `client-interpreters.md`: observed CSS-to-executable-sink bridge; style/exfil alone is not XSS. |
| Trusted Types Bypass | Existing mechanism guide + `defense-edges.md`: policy output and caller control. |
| AI Agent Weaponization & Prompt-to-XSS | `derived-consumers.md`: controlled model output into executable renderer; prompt injection is separate. |
| Polymorphic & AI-Generated Payloads | Existing exploratory queue + `defense-edges.md`: candidate generator, not a new mechanism. |
| Sanitizer Bypass Techniques | Existing mechanism guide + `defense-edges.md`: pin sanitizer/version/config and actual sink. |
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
