# Client Interpreters and Unusual XSS Consumers

Load from `idea-tree.md` when a mapped input, plausible sink, or unexpected
consumer suggests one of these client interpreters. `dom-xss` owns the
source-to-sink trace and browser proof; `xss-lifecycle` owns later consumers.
Use the rows as idea lenses; a new interpreter need not be listed here. When
testing a claimed path, observe the caller and use an inert marker or contrasting
observation if it helps identify the missing edge. A technology label alone is
not a proven vector.

| Trigger and question | What can distinguish a claimed path |
| --- | --- |
| **Client-side templates:** does the application compile attacker-controlled text as a template, or merely interpolate it as data? Map the compiler call, framework/version, trust helper, and eventual DOM insertion. | Compare an inert template-expression marker in the actual compile path with ordinary escaped interpolation. No attacker-controlled string entering a compiler → no client-template injection. JSX source snippets in an upstream write-up are not evidence that production React compiles JSX from data. |
| **Web Components / shadow DOM:** does a reachable custom-element lifecycle callback parse a controlled attribute/slot/message as HTML, script, URL, or template? Does the component clone content or cross a shadow boundary? | Trace `attributeChangedCallback`, `connectedCallback`, slot/clone and sink with a marker or source trace. A developer-defined custom element containing `eval` is not proof an attacker can define it; if the tested attribute never reaches that callback, retire that edge while retaining other slots, messages and consumers. Shadow DOM is not an XSS defense or proof by itself. |
| **SVG, MathML and XML:** is the value parsed in the relevant namespace, inline in an HTML page, in an image context, or in a separate document? Will a downstream client reserialize/reparse it? | Compare exact response/render mode and resulting DOM, plus text-only or image-context control. A string beginning with `<svg` or an uploaded image URL does not prove script execution; distinguish inline markup, `<img>` rendering, and navigated documents under delivered CSP. Use `mechanism-ideation.md` to investigate a suspected reparse; claim mXSS only after the same sanitized markup changes structure across an observed parser transition. |
| **CSS-to-script / stylesheet-controlled config:** is an attacker-controlled CSS value later read by JavaScript and used in an HTML, URL, template or script sink? Is a style tag itself permitted and rendered? | Inspect the style consumer and its later JS call. A CSS `url(javascript:...)` example alone is not a modern browser execution path; if CSS remains only styling or its value enters `textContent`, classify separately as CSS influence or inert XSS. Do not equate CSS exfiltration with XSS. |
| **Import maps and module resolution:** can the attacker influence an import map *before* a reachable module specifier resolves, or select a module URL through an observed config writer? Which CSP/module fetch checks apply? | Compare the resolved module specifier and request with a fixed-map control. A user-supplied JSON blob never installed as an import map cannot redirect execution. A later map cannot change an **already resolved** specifier, though it may affect eligible imports not yet resolved; check the actual order rather than declaring all late maps inert. The upstream's `data:` module example is configuration-dependent, not a generic CSP bypass. |
| **WebAssembly:** does a reachable JS caller accept controlled module bytes, imports, exported data, or a return value that it inserts into an executable DOM/JS sink? | Trace JS glue, module source and returned value. WASM does not independently obtain browser DOM authority; no controlled JS import/caller-to-sink edge → not an initial XSS primitive. If attacker JS already runs, distinguish post-XSS impact from the entry point. |
| **Service Workers:** can an authorized page register an attacker-controlled, browser-acceptable same-origin worker script, or send controlled messages to an existing worker that produces a later unsafe document? | Verify actual worker registration or message handler, scope, response and browser render. A proposed `data:` registration is not a valid shortcut; absent a controllable script resource or handler-to-page sink, do not claim a worker XSS route. Do not register persistent workers in a shared/third-party origin merely to test an idea; isolate and clean up an owned fixture. |
| **Content-type/charset interpretation:** does a user-controlled response actually navigate/render as HTML or XML because of its delivered MIME, charset, `nosniff` posture and browser behavior? | Capture exact headers, response bytes and victim navigation in the claimed browser; compare explicit safe MIME and `nosniff` controls. An inert download, JSON API response, or image-context render is not browser document XSS. Legacy sniffing anecdotes are browser/version dependent. |
| **Console/DevTools:** is a developer-only log merely displaying hostile text, or does an application-owned console/dashboard transform it into an executable DOM? | Trace an observed renderer and plausible approved victim path. An instruction to paste code is social-engineered self-XSS, not a cross-user XSS finding; don't persuade staff to perform an action to complete a test. |

**Related owners:** `dom-xss` for browser sources/sinks, `upload-surface`
for uploaded content and response headers, `xss-lifecycle` for later views,
`xss-technology-research` for a concrete framework/browser fingerprint. Browser
execution in the claimed consumer—not a static token, log line or request—is
the XSS proof boundary. `references/defense-edges.md` handles delivered CSP and
Trusted Types when those are the first acting blockers.

**Provenance:** idea families from pinned Advanced-XSS README commit
`7d529fe86fe8bdef73b393db9274e427cf637182`; this reference repairs or
conditions its examples rather than importing them. Primary constraints:
WHATWG import-map processing
(https://html.spec.whatwg.org/multipage/webappapis.html#import-maps),
Service Worker registration
(https://w3c.github.io/ServiceWorker/#navigator-service-worker-register),
WebAssembly JS interface
(https://webassembly.github.io/spec/js-api/), and HTML MIME handling
(https://html.spec.whatwg.org/multipage/urls-and-fetching.html).
