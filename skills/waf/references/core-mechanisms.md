# Shared WAF Mechanism Questions

Load only after `waf` has a reproducible blocker and the app facts / relevant
ResearchMap cards do not yet explain a plausible bypass. This is not a guaranteed bypass
catalogue or a live-probe checklist. Each row is a way to
choose one falsifiable question about the *acting control*. A vendor name alone
does not establish its deployed rules, configuration, coverage, or request
budget. Follow `waf-live-policy` and the owning vulnerability lane; stop on its
challenge, rate, ownership, or scope boundary.

For the observed request, identify **the representation inspected by the
control**, **the representation consumed downstream**, and **the semantic value
that must be preserved**. If that chain cannot be stated, research or make an
inert discriminator before constructing a class-specific candidate. Do not
repeat an equivalent mutation after its predicted stage was falsified.

## Conditional mechanisms

### Inspection surface and component coverage

- **Recognition signal:** Same legitimate route and marker behave differently
  when placed in request components or fields the origin accepts; edge logs or
  rule IDs, if available, narrow what was inspected.
- **Precondition:** The downstream application actually consumes the alternate
  component and it carries the same class-relevant meaning; account and route
  authorization remain comparable.
- **Discriminating check:** Use inert markers to trace which component the
  origin consumes; compare the exact downstream value from matched requests.
  When policy permits, separately compare the known-blocked value across the
  suspected inspected and alternate components. Do not infer filter passage
  from an inert marker's acceptance.
- **Negative control:** The known-blocked value in the original inspected and
  consumed component still produces the blocked baseline under matched conditions.
- **Counter-explanation:** Origin ignored the alternate field, cache/auth changed,
  or request-body size/truncation changed reachability without a useful bypass.
- **Sources to ask about coverage:** [AWS request components](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields-list.html), [AWS oversize handling](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html).

### Decoding and normalization order

- **Recognition signal:** Two encodings of an inert value are classified
  differently by the control but converge, or diverge, at a later decoder.
- **Precondition:** An evidenced transform/decoder accepts the representation;
  the value remains meaningful to the final vulnerability-class consumer.
- **Discriminating check:** Trace raw bytes, inspected form where observable,
  origin value, and later parse with the semantic input held constant.
- **Negative control:** Use a representation that bypasses no stage or decodes
  to a harmless literal; compare the same route/session/time.
- **Counter-explanation:** The origin rejects or normalizes both forms, a client
  pre-encodes differently, or the suspected decoder does not run on this field.
- **Sources to ask about transformations:** [AWS ordered text transformations](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html), [OWASP HTTP parameter pollution](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution/). Browser-specific HTML/JS interpretation belongs to `xss-waf-evasion`.

### Routing and body representation

- **Recognition signal:** The same intended route or field is treated
  differently across accepted content types, parameter shapes, or routing
  representations.
- **Precondition:** The target's origin parses the alternate request into the
  same relevant value/route, with comparable auth, side effects, and (when
  applicable) a victim-reachable transport.
- **Discriminating check:** Change one accepted representation, then compare the
  control result and actual origin route/value; do not rely on status alone.
- **Negative control:** An alternate shape that the origin does *not* consume
  demonstrates why an apparent edge pass can be meaningless.
- **Counter-explanation:** A route mismatch, method-specific permission,
  duplicate-parameter policy, or body parser failure explains the response.
- **Sources to ask about disagreement:** [OWASP HPP testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution/), [AWS request components](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields-list.html), [SFADiff study](https://www.cs.columbia.edu/~angelos/Papers/2016/ccs-sfadiff.pdf), [WAFFLED study](https://akhavani.net/publications/waffled/), [PortSwigger historical request-interpretation case](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie). Use `bypass` for broader parser/access questions; historical cases are not current target bypasses.

### Policy exceptions and rule selection

- **Recognition signal:** Logs, rule IDs, path-specific behavior, or action
  changes suggest the policy selects or excludes different routes/components.
- **Precondition:** The observed exception/selection applies to the same
  account, request path, and downstream consumer. Product docs alone are not
  target configuration evidence.
- **Discriminating check:** Hold client and semantic value fixed across two
  authorized, comparable paths or components; read matched-rule evidence when
  available.
- **Negative control:** The known protected path/component still blocks under
  the same conditions.
- **Counter-explanation:** A cache, login redirect, app-level validation, or
  origin route difference changed the response, not the WAF policy.
- **Sources to ask about configuration:** [Cloudflare managed-rule troubleshooting](https://developers.cloudflare.com/waf/managed-rules/troubleshooting/), [Cloudflare exceptions](https://developers.cloudflare.com/waf/managed-rules/waf-exceptions/), [Akamai protections](https://techdocs.akamai.com/cloud-security/docs/set-protections), [Akamai exception selectors](https://techdocs.akamai.com/application-security/reference/exception-selector-values), [Fastly Next-Gen WAF rules](https://www.fastly.com/documentation/guides/next-gen-waf/rules/about-rules/), [OWASP CRS tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/) and [FAQ/paranoia levels](https://coreruleset.org/faq/).

### Time, client, and challenge behavior

- **Recognition signal:** Identical controlled input changes outcome with time,
  legitimate session, challenge state, or a rate window.
- **Precondition:** Scope and rate policy permit another comparison; the
  difference can be reproduced without rotating identities or defeating a
  challenge.
- **Discriminating check:** Preserve a green control and send the same inert
  request in the permitted session/window; compare challenge/rate signals with
  payload-driven changes.
- **Negative control:** Unchanged benign traffic under the same conditions
  changes too; that points away from a payload-specific rule.
- **Counter-explanation:** Transient availability, cache, expired auth, or
  client-side retry behavior; a 200 after a challenge is not a filter bypass.
- **Sources to ask about signals:** [Cloudflare attack score](https://developers.cloudflare.com/waf/detections/attack-score/) and [managed-rule troubleshooting](https://developers.cloudflare.com/waf/managed-rules/troubleshooting/). Follow `captcha-policy` and `waf-live-policy`; do not rotate clients/IPs to evade an active safeguard.

## Return to the owning lane

Select at most the mechanism *supported by the current observation*, record
its recognition signal, source/target evidence distinction, precondition,
predicted result, negative control, counter-explanation, and stop rule. If no
mechanism fits, use `technology-research` for the concrete missing stage or one
small inert discriminator; do not sweep these rows. A supported WAF pass only
answers which representation crossed this control. The XSS, SSRF, SQLi, access,
or other lane must separately establish its downstream value and impact.

Executed probes belong to Attempts; stable target facts to MapStore; a portable
mechanism goes to ResearchMap only after source-backed admission review. Never
promote a vendor doc, an untested bypass string, or a target-specific payload as
a reviewed portable card.
