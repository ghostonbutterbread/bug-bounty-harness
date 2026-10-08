# XSS Consumer and Rule-Specific Source Library

These are retrieval leads for a **concrete XSS parser, sanitizer, rule, and
consumer question**, not a corpus of guaranteed bypasses. For shared WAF
inspection/normalization/exception questions, first use `waf`'s
`references/core-mechanisms.md`. Prefer the target's observed path and deployed
version. Primary docs describe possibilities, not the target's actual settings;
historical research is not a current product vulnerability. Record what a
source changed in the next test. ResearchMap cards remain the reviewed portable
store; MapStore owns target observations.

## Browser grammar and XSS contexts

- [WHATWG HTML parsing](https://html.spec.whatwg.org/multipage/parsing.html), [Encoding](https://encoding.spec.whatwg.org/), [URL](https://url.spec.whatwg.org/) — decide which exact representation the browser parser accepts.
- [OWASP XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html) and [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — candidate history paired with correct output-context boundaries; verify browser and version.
- [PortSwigger XSS contexts](https://portswigger.net/web-security/cross-site-scripting/contexts), [interactive cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet), [encoding techniques](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings) — select by context, event, browser and decoder, not by payload count.

## XSS-rule-specific documentation

- [AWS WAF XSS match statement](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-xss-match.html), [AWS managed baseline rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html) — distinguish XSS-specific rule semantics from the shared request-coverage question; a customer's deployed selection remains unknown without evidence.
- [OWASP CRS 941 XSS rule source](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf), [version-specific XML-attribute advisory](https://github.com/coreruleset/coreruleset/security/advisories/GHSA-6jp8-c2w2-x7wr) — match the rule ID and deployed release; `main` is mutable.

## XSS parser and sanitizer research

- [NIST combinatorial XSS/WAF study](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=931831), [mutation-XSS foundational paper](https://research.chalmers.se/en/publication/189934), [DOMPurify attack classes](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-%26-Bypass-History), [PortSwigger DOMPurify mutation study](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss), [Vue script gadgets](https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets) — later browser/framework interpretation requires matching version, parser and sink.
- [PortSwigger tag-name transformation](https://portswigger.net/research/whats-in-a-tag-name-javascript-apparently), [security features colliding](https://portswigger.net/research/when-security-features-collide), [DOM polyglot case study](https://portswigger.net/research/finding-dom-polyglot-xss-in-paypal-the-easy-way), [XSS research index](https://portswigger.net/research/cross-site-scripting-research) — historical cases identify stage differences, not target bypasses.

## Optional tools and corpus leads

- [Hackvertor](https://github.com/hackvertor/hackvertor) for controlled encoding comparisons; [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) for DOM source/sink leads; [Playwright browsers](https://playwright.dev/docs/browsers) for consumer checks; [CSP Evaluator](https://github.com/google/csp-evaluator) for delivered policy analysis.
- [XSStrike](https://github.com/s0md3v/XSStrike), [Dalfox](https://github.com/hahwul/dalfox), [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection), [Domato](https://github.com/googleprojectzero/domato), [archived Firing Range](https://github.com/google/firing-range) — discovery and local fixtures, not proof or a mandate to scan live targets.
- [PortSwigger cheat-sheet data](https://github.com/PortSwigger/xss-cheatsheet-data) — **link only**. Its repository license does not permit republishing a derivative cheat sheet; do not copy the JSON into this skill or ResearchMap.
