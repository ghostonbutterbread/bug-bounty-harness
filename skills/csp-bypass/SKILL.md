---
name: csp-bypass
description: Analyze CSP bypass paths when a plausible XSS source reaches a browser consumer.
---

# CSP Bypass

Use this when a plausible attacker-controlled source reaches a browser-rendered consumer but an enforced Content Security Policy (CSP) appears to block execution. CSP is a browser execution/resource policy, not a sanitizer. The task is to learn whether the policy blocks this *actual path*, and whether the application itself has a trusted execution path that consumes controlled input. Research supplies hypotheses; target-specific policy and browser evidence decide applicability.

## When to use

- A CSP violation is the apparent reason an observed XSS candidate did not execute.
- A source-to-sink path exists and the policy's script trust model may permit an alternate route.
- You need to assess a nonce/hash policy, `strict-dynamic`, allowlisted script origins, trusted loaders, or a CSP analyzer warning.

Do not elevate a weak policy or a named CSP “bypass” to XSS without a controlled input and an executable browser consumer. For a purely defensive policy audit, report configuration risk separately.

## Mental model

CSP bypasses usually do **not** make the browser ignore a valid policy. They use something the policy already trusts or allowed: a trusted host's executable endpoint, an unsafe code gadget in an authorized script, a loader that confers trust to a child script, an over-broad execution keyword, or a reused nonce. The app can therefore execute attacker-controlled behavior without violating the policy. Alternatively, the policy may not be enforced on the actual document at all. CSP does not repair the underlying injection.

## Procedure

### 1. Establish the exact effective policy

Capture the response and browser behavior for the final document containing the consumer. Record every enforced `Content-Security-Policy` response header, `Content-Security-Policy-Report-Only` header, and applicable `<meta http-equiv>` policy. Report-Only reports but does not block. Multiple enforced policies are cumulative; a later policy cannot loosen an earlier one. Note redirect/final URL, frame/document origin, browser/version, and whether the consumer actually mounted.

Resolve the directive for the operation: `script-src-elem` / `script-src-attr` and their fallback through `script-src` then `default-src` as applicable. Do not assume `default-src` covers every directive. Obtain the actual console violation or successful load/execution evidence; a CSP report is about a blocked operation, not proof of exploitable input. Remember meta-delivered CSP has timing and directive limitations; prefer the final response header when evaluating the deployed policy.

### 2. Trace source to the first executable consumer

Record attacker-controlled source, accepted representation, storage/lifecycle, all transforms, final HTML/DOM/script consumer, frame and origin, and browser result. Keep WAF rejection, sanitizer output, template behavior, CSP blocking, and consumer reachability as separate observations. If there is no executable consumer, the result is not a CSP bypass candidate. If execution happened in an allowed path without a policy violation, CSP may be irrelevant to the proof rather than “bypassed.”

### 3. Branch on the policy's actual trust mechanism

Start with direct policy failures before chasing subtle gadgets: no effective `script-src`/`default-src`, an effective `unsafe-inline`, broad script scheme (`http:`/`https:`), wildcard, or executable `data:`/`blob:` source can make the supposed barrier permissive. Check `object-src`/its fallback for legacy plugin execution only if the target browser and runtime actually support that path. A token's mere textual presence is not its effective behavior; resolve nonce/hash and browser rules first. If the policy is already permissive, classify the cause and prove only the application path needed to show real impact—don't invent a more exotic bypass.

**Host/path matching and redirects:** a path-qualified source is not always a hard boundary after a redirect. CSP ignores the source expression's path component after a resource redirect to avoid cross-origin path leaks; the destination still has to match applicable scheme/host/port conditions. Check the actual redirect chain and current browser/spec semantics, rather than assuming `/trusted/` limits the final path. A redirect endpoint matters only if it is on an effective script source path and the final response is executable in the target browser.

**A. Host/scheme allowlists (`self`, host, wildcard, scheme, `data:`/`blob:`)**

For only the effective allowed origins, inspect whether the app or trusted origin has a relevant executable resource: JSONP, a user-uploaded file served as script, a callback/config endpoint, a script-serving redirect, an obsolete framework/library, or a path that returns attacker-controlled JavaScript. Check origin, path, redirect chain, MIME/nosniff behavior, and whether the loaded content can be influenced. A broad host list or `self` is a lead, not proof; a CSP evaluator's known-host match is also only a lead. Do not probe unrelated domains from a published host list.

**B. JSONP / callback endpoints**

A JSONP endpoint is relevant only if it is on an effective trusted script origin and returns executable JavaScript that the attacker can meaningfully influence (for example, callback selection or an unsafe response body). Confirm endpoint behavior and script-context execution; JSON APIs returning inert JSON are not automatically JSONP. Some known endpoints require `unsafe-eval` or other conditions, so test the full target policy rather than assuming the hostname alone suffices.

**C. Framework or application script gadgets**

Inspect code already loaded by a trusted/nonce-authorized script for a DOM gadget: a selector or attribute-driven feature that reads attacker-injected markup and passes it to a code-capable interpreter, template compiler, URL loader, or dynamic script constructor. Distinguish two important cases:

- **Interpreter/template gadget:** an already trusted app/framework parser treats attacker-controlled DOM text/attributes as an expression or template. This can execute without a new `<script>` request and may not produce a CSP violation. Whether it works can depend on framework version/mode and on `unsafe-eval`; trace the actual compiler/parser path rather than assuming every template feature is eval-gated.
- **Dynamic script gadget:** trusted code reads attacker-controlled DOM/configuration and creates or selects a script URL. Under a nonce/hash + `strict-dynamic` policy, a trusted script's non-parser-inserted child can inherit trust; without that policy, the relevant source list must still authorize the resource.

Candidate patterns include AngularJS expression/template handling, HTML-to-DOM helpers, selector-based gadgets, and application-specific loaders. Trace exact caller → selector/config → controlled value → dangerous consumer. Framework presence, generic gadget catalogs, or inert markup alone do not establish a gadget. Research whether it fits the *observed* library version and runtime mode.

**D. Nonce/hash-authorized root scripts and `strict-dynamic`**

For a nonce/hash policy, inspect the authorized scripts as part of the trusted computing base. Check whether controlled input can reach a nonce-bearing inline block, the `src`/URL builder of an authorized dynamic loader, or a code-capable sink in a trusted script. With `strict-dynamic`, supporting CSP3 browsers trust non-parser-inserted scripts loaded by a nonce/hash-trusted script and ignore host/scheme/`self` sources for relevant script checks; older CSP behavior can fall back to those allowlists. Map the exact root script → loader decision → child request and test the target browser. Do not treat `strict-dynamic` itself as a flaw; a safe loader is its intended design.

**E. Nonce reuse, cache, and nonce read paths**

Observe nonce values across normal fresh responses and, if permitted, the same owned test account/session plus a clean owned session. Check cache headers/variants and whether reuse is session-bound; do not target other users, brute-force values, or induce shared cache changes. A nonce in the page source is expected and is not by itself a bypass. Nonce-read/exfil ideas (for example a parser/DOM/CSS-side-channel condition) require a concrete injection location, a browser behavior that exposes the value, and a permitted observable channel; verify against current browser behavior and HTML nonce-hiding rules. The 2023 study found reuse on at least two sampled requests at 598 of 2,271 sites with nonce-based CSP (561 of those across sessions); this is an old crawl sample, not a present-day prevalence estimate or claim about a target.

**F. `unsafe-inline`, hashes, event attributes, and `unsafe-eval`**

Check whether the token is effective for the specific target browser. For JavaScript string-code generation, each policy's eval check consults that policy's `script-src` list (falling back to its `default-src`), not the separate `script-src-elem` or `script-src-attr` lists. Modern browsers ignore `unsafe-inline` in a source list containing a valid nonce/hash (and certain other conditions); legacy behavior can differ. Hashes authorize exact script text, and `unsafe-hashes` has narrower event-handler implications—verify applicable syntax, element type, and exact content. `unsafe-eval` enables string-to-code paths such as `eval`, `Function`, and string timers where the browser/API applies it, but does not create attacker control. `wasm-unsafe-eval` permits WebAssembly compilation without enabling JavaScript string evaluation; `trusted-types-eval` can allow TrustedScript-valued eval sinks when Trusted Types is required and supported. Trace controlled input into the actual reachable compilation sink.

**G. Missing `base-uri` and relative script URL rewriting**

A missing `base-uri` matters for an XSS chain only when input can introduce/affect a base element and a trusted relative URL is subsequently resolved against the changed base. Confirm parser order, element reachability, actual resolved URL, final response, and execution. If no relative trusted script load depends on the base URL, record a hardening gap—not a CSP bypass.

**H. Other directive gaps and post-execution effects**

`object-src`, `base-uri`, `form-action`, `frame-ancestors`, and worker/resource directives matter only for a specific supported browser feature/path. Distinguish script execution from what script can later send out: `connect-src` is not a universal egress control, and a restricted fetch/XHR path does not prove execution was blocked. Keep impact claims separate and obey the selected XSS lane's permitted proof boundary.

**I. Delivery and browser discrepancies**

Check accidental Report-Only deployment, missing policy on one route/template, conflicting policies, header/meta differences, redirects/frames, cached responses, and browser/CSP-level semantics. Compare the policy the browser received with the policy shown in source/config. Prefer observed target-browser behavior over user-agent strings or assumed version support.

### 4. Use analyzers and research appropriately

Use Google CSP Evaluator to triage risky keywords, missing `object-src` / `base-uri`, host allowlists, known JSONP/AngularJS hosts, and wildcards. It is not a scanner for the target application's runtime gadgets, and its output is not proof. Follow a candidate back to the exact effective directive, endpoint or loaded script, and controlled source-to-sink edge. Use the sources below to derive a narrow mechanism, preconditions, smallest check, and falsifier; keep a failed mechanism's negative local to that edge.

### 5. Prove or falsify in the authorized browser

Run a control and a mechanism-matched candidate on the actual consumer, using owned/disposable state where the XSS lane requires it. Confirm whether the browser executed controlled behavior, which origin/frame ran it, and whether an enforced directive blocked it. Do not use external callbacks, read secrets, access another user's session, persist public payloads, or trigger victim-visible effects as a shortcut. Preserve sanitized headers/DOM/console evidence and cleanup owned state.

### 6. Classify and report

Keep three outcomes distinct:

- **Policy weakness:** analyzer/specification indicates risky configuration; no applicable exploit path proven.
- **Plausible CSP bypass:** mechanism has a concrete source, trusted path and consumer, but execution is unproven.
- **Confirmed XSS despite CSP:** controlled input executes in the claimed consumer under the actual enforced policy.

Record exact policy and delivery, browser, directive, controlled source, transforms, trusted script/endpoint/gadget, first executable sink, observed execution/violation, impact boundary, and residual questions. A failure to execute falsifies only the tested mechanism/path, not every CSP branch.

## Pitfalls

- CSP is not a sanitizer; a blocked request or violation is not a completed XSS assessment.
- A `self`, CDN, or JSONP warning is not proof until the actual resource and attacker-control requirement are verified.
- A nonce is designed to be visible to scripts already trusted; a nonce value seen once is not a bypass.
- `strict-dynamic` shifts trust from host lists to trusted loaders; inspect loader data flow and browser level.
- A script gadget may execute through already trusted code without a blocked script request; inspect DOM consumers as well as network violations.
- Old allowlist databases and papers describe historical endpoints/measurements; current code, response behavior, and browser evidence control.
- Do not use CSP analyzer output to overstate impact or claim CSP is wholly ineffective.

## Research references

**Normative/browser semantics**
- W3C, Content Security Policy Level 3: https://www.w3.org/TR/CSP/ — effective directives, fallback, nonce/hash handling, `strict-dynamic`, meta policies, nonce hiding, Strict CSP guidance.
- Google Web.dev, Strict CSP: https://web.dev/articles/strict-csp — modern nonce/hash + `strict-dynamic` deployment model and older-browser fallback.
- MDN, CSP guide: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP — browser-facing policy and reporting concepts.

**Allowlist and gadget bypass families**
- Google CSP Evaluator: https://csp-evaluator.withgoogle.com/ — triage tool; its code documents checks for wildcard sources, missing directives, `self`, known JSONP/AngularJS and object allowlists: https://github.com/google/csp-evaluator/blob/master/checks/security_checks.ts.
- Weichselbaum et al., “CSP Is Dead, Long Live CSP!”: https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/ — historical measurement and analysis of host allowlist weakness; don't reuse its endpoint corpus blindly.
- Lekies et al., “Code-reuse attacks for the Web: Breaking Cross-Site Scripting Mitigations via Script Gadgets” (CCS 2017): https://research.google/pubs/code-reuse-attacks-for-the-web-breaking-cross-site-scripting-mitigations-via-script-gadgets/ — trusted application/framework code can interpret injected markup despite tag/event-handler restrictions.
- Roth et al., “Assessing the Impact of Script Gadgets on CSP at Scale” (2020): https://swag.cispa.saarland/papers/roth2020gadgets.pdf — measured gadget sideloading conditions; results are dated and not a target verdict.

**Nonce and cache failures**
- Golinelli et al., “The Nonce-nce of Web Security: an Investigation of CSP Nonces Reuse” (2023): https://arxiv.org/abs/2309.07782 — observed nonce reuse and cache/server causes in its historical sample; use only to motivate low-impact checks on owned requests.
- Mozilla Bug 1871112: https://bugzilla.mozilla.org/show_bug.cgi?id=1871112 — specific parser/nonce-visibility report; assess current fixed browser behavior, not just the historical PoC.

Use the specification and current target-browser output first; use papers and issue reports to generate mechanism hypotheses. A literature result does not prove the target is affected.
