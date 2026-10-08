# XSS/WAF Source Library

These are **retrieval leads for a concrete control + parser + consumer
question**, not a corpus of guaranteed bypasses. Prefer the current deployed
rule/version and the observed application path. Primary docs describe possible
configuration, not the target's actual settings; historical research illustrates
mechanisms, not current product vulnerabilities. Record the source and what it
changed in the next test. ResearchMap cards remain the reviewed portable store;
MapStore owns target observations.

## Browser grammar and XSS contexts

- [WHATWG HTML parsing](https://html.spec.whatwg.org/multipage/parsing.html), [Encoding](https://encoding.spec.whatwg.org/), [URL](https://url.spec.whatwg.org/) — decide which exact representation each parser accepts.
- [OWASP XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html) and [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — candidate history paired with correct output-context boundaries; verify browser and version.
- [PortSwigger XSS contexts](https://portswigger.net/web-security/cross-site-scripting/contexts), [interactive cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet), [encoding techniques](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings) — select by context, event, browser and decoder, not by payload count.

## Vendor/control documentation: identify inspected component and policy

- **Cloudflare:** [managed-rule troubleshooting](https://developers.cloudflare.com/waf/managed-rules/troubleshooting/), [attack score](https://developers.cloudflare.com/waf/detections/attack-score/), [exceptions](https://developers.cloudflare.com/waf/managed-rules/waf-exceptions/) — rule, score, action and path-specific exception are different questions.
- **AWS WAF:** [XSS match statement](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-xss-match.html), [components to inspect](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields-list.html), [ordered text transformations](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html), [managed baseline rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html), [oversize behavior](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html) — a selected rule does not imply full-request coverage or a specific customer configuration.
- **ModSecurity/OWASP CRS:** [941 XSS rule source](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf), [FAQ/paranoia levels](https://coreruleset.org/faq/), [false-positive tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), [version-specific XML-attribute advisory](https://github.com/coreruleset/coreruleset/security/advisories/GHSA-6jp8-c2w2-x7wr) — pin the deployed release/rule ID; `main` is mutable.
- **Akamai:** [App & API Protector Hybrid protections](https://techdocs.akamai.com/cloud-security/docs/set-protections), [exception selectors](https://techdocs.akamai.com/application-security/reference/exception-selector-values) — rule group, action and selector require observed deployment evidence.
- **Fastly:** [Next-Gen WAF rules](https://www.fastly.com/documentation/guides/next-gen-waf/rules/about-rules/) — distinguish signal, exclusion, precedence and action.

## Primary mechanism studies: extract preconditions, not strings

- [SFADiff](https://www.cs.columbia.edu/~angelos/Papers/2016/ccs-sfadiff.pdf), [WAFFLED](https://akhavani.net/publications/waffled/), [NIST combinatorial XSS/WAF study](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=931831), [OWASP HTTP Parameter Pollution](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution/) — differential parser/request coverage and generated rule hypotheses; classification does not prove a target XSS.
- [Mutation-XSS foundational paper](https://research.chalmers.se/en/publication/189934), [DOMPurify attack classes](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-%26-Bypass-History), [PortSwigger DOMPurify mutation study](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss), [Vue script gadgets](https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets) — later browser/framework interpretation; require matching version, parser and sink.
- [PortSwigger tag-name transformation](https://portswigger.net/research/whats-in-a-tag-name-javascript-apparently), [security features colliding](https://portswigger.net/research/when-security-features-collide), [phantom `$Version` cookie](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie), [DOM polyglot case study](https://portswigger.net/research/finding-dom-polyglot-xss-in-paypal-the-easy-way), [XSS research index](https://portswigger.net/research/cross-site-scripting-research) — recognize stage mismatches and browser-specific consumers; historical cases are not current bypass claims.

## Optional tools and corpus leads

- [Hackvertor](https://github.com/hackvertor/hackvertor) for controlled encoding comparisons; [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) for DOM source/sink leads; [Playwright browsers](https://playwright.dev/docs/browsers) for consumer checks; [CSP Evaluator](https://github.com/google/csp-evaluator) for delivered policy analysis.
- [XSStrike](https://github.com/s0md3v/XSStrike), [Dalfox](https://github.com/hahwul/dalfox), [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection), [Domato](https://github.com/googleprojectzero/domato), [archived Firing Range](https://github.com/google/firing-range) — discovery and local fixtures, not proof or a mandate to scan live targets.
- [PortSwigger cheat-sheet data](https://github.com/PortSwigger/xss-cheatsheet-data) — **link only**. Its repository license does not permit republishing a derivative cheat sheet; do not copy the JSON into this skill or ResearchMap.
