# Defense Edges and Representation Ideas

Load from `idea-tree.md` only once an observed control (or a concrete
stack/browser signal) changes the candidate queue. This is a question map, not
a WAF-bypass recipe. `waf-live-policy`/`waf`/`xss-waf-evasion` own filter
classification and controlled probing; `xss-technology-research` owns
version-specific research; the selected XSS lane owns browser proof. Keep
source-reported claims separate from a target's delivered policies.

| Observed edge | Evidence and controlled discriminator | What would falsify or reroute it |
| --- | --- | --- |
| **Sanitizer / browser parser disagreement** | Compare exact library/version/config, sanitized DOM or string, serialization, later parser and final DOM. `mechanism-ideation.md` owns mXSS versus application rewrite. For native Sanitizer API or a framework trust helper, identify which mode/options and sink actually run; research only that implementation. | No reparse, no controlled input, or no change to the same sanitized markup → not mXSS. Post-sanitize app modification belongs to composition, not a library bypass. Historical DOMPurify vectors are not evidence of a current version flaw. |
| **Trusted Types policy and caller** | Inspect the enforced `require-trusted-types-for` directive, policy definition, caller-controlled input and the exact `TrustedHTML`/script URL output. Compare controlled versus fixed caller input at the same sink. | A permissive policy can make unsafe use possible, but its mere existence is not an exploit. No controllable policy call, or a blocked sink with no allowed alternative, closes that path; a Report-Only header is not enforcement. |
| **CSP nonces, hashes, allowlisted callers and cache** | Record the *delivered* policy, actual executing script element, nonce/hash lifetime, trusted script loader and attacker-controlled selector/argument. For a cache-related hypothesis, compare a safely owned response's nonce/policy and cache key across repeat requests without trying to harvest another user's secret. | A CSS selector seeing `script[nonce]` is **not** assumed to expose nonce bytes; HTML nonce hiding can remove the attribute value from CSS-visible state. A stale/static nonce claim needs proof of nonce reuse plus an executable injection point; a CSP violation alone, a CSS URL request, or source HTML alone is not XSS. Load `xss-technology-research` only for a matching implementation. |
| **WAF / app filter with changed representation** | Keep the same owned route and final consumer. Compare one differing input representation against edge decision, origin value, final DOM and browser result; use the existing `xss-waf-evasion` four-gate proof. | A 200 response, string reflection or vendor label proves neither browser execution nor victim reachability. No plausible executable consumer → retain a filter observation, not an XSS bypass. |
| **Encoding, Unicode, charset and mixed grammars** | Load `parser-stage-character-variants.md`; name the exact decoder, normalizer, browser parser or charset that changes meaning. Compare raw vs transformed bytes at that stage and a text-only control. | Percent-encoded syntax, fullwidth punctuation, nested entities or a polyglot string are inert without the corresponding real stage. A generative/polymorphic payload is a *candidate generator*, not an automatic distinct mechanism. |
| **CSS-only influence or style exfiltration** | If controlled CSS is later read as a JS/URL/template input, branch to `client-interpreters.md`. If only network requests leak data or styles shift UI, classify that impact separately under scope. | A stylesheet request is not script execution; no CSS-to-executable-consumer edge means no XSS finding. Nonce extraction via CSS alone is especially configuration/browser dependent. |

When a version-specific source suggests a technique, return a compact research
packet: observed fingerprint, source claim, prerequisites, one safe discriminator
and a falsifier. Do not clone the upstream's code snippets or run a payload
matrix in place of locating the acting control. `mechanism-ideation.md` and the
selected lane retain positive reachability and proof requirements.

**Sources:** pinned Advanced-XSS README commit
`7d529fe86fe8bdef73b393db9274e427cf637182` (inspiration; examples not
validated); WHATWG nonce hiding
https://html.spec.whatwg.org/multipage/urls-and-fetching.html#nonce-attributes;
W3C Content Security Policy Level 3 https://www.w3.org/TR/CSP3/;
Trusted Types https://www.w3.org/TR/trusted-types/;
DOMPurify README https://github.com/cure53/DOMPurify.
