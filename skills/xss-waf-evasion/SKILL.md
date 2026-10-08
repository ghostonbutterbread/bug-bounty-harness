---
name: xss-waf-evasion
description: Use when XSS input is blocked by WAF or app filtering.
---

# XSS WAF Evasion

Load after `xss`, its observed reflected/stored/DOM/blind lane, and
`xss-payload-engineering` when a plausible executable consumer meets a
reproducible WAF or application-filter boundary. `waf` owns the general adaptive
blocker loop; `waf-live-policy` owns live rates, challenge and stop decisions;
the XSS lane owns browser proof and impact. This skill connects **a candidate
filter bypass** to **a value the actual consumer can execute**. It does not turn
a filter hit into a warm vector without a plausible consumer, nor does it claim
that a WAF protects a DOM-only source that never crosses it.

## XSS handoff from the shared loop

`waf` owns the baseline, acting-control classification, `map-store`
`app-facts`/`dedupe` and relevant ResearchMap retrieval, sufficiency gate,
focused research trigger, controlled comparison, and learning destinations.
Do not repeat that loop here. Carry its observed control/representation
differential into this XSS-only packet; leave unknowns explicit:

```text
attacker-controlled source and request representation
plausible sink and HTML/attribute/URL/script/JSON/DOM grammar; later consumer
surviving primitives, exact value before/after sanitizer, decoder or reparse
browser, framework, delivered CSP, and who sends/encounters the result
```

A reject-on-match filter differs from a sanitizer that rewrites output; a DOM-only
source not crossing the WAF belongs in `dom-xss`, not a WAF bypass. If the layer
is still unclear, return to `waf` rather than assigning a vendor trick.

## Class-specific candidate and proof

1. **Apply `waf`'s sufficiency gate to XSS:** A plausible bypass of the
   current blocker also needs a path from the altered representation to an
   executable parser in the real flow. Write one causal sentence: what the
   control sees, what the origin/browser interprets differently, and why the
   actual victim flow could carry it. The shared reference
   `skills/waf/references/core-mechanisms.md` answers general inspection and
   policy questions; `references/technique-questions.md` asks XSS parser and
   delivery questions. Neither is a payload bank.
2. **If no:** Name the missing XSS-specific consumer, sanitizer/reparse,
   framework, or browser/CSP prerequisite. Use `xss-technology-research` and
   `references/vendor-and-mechanism-sources.md` for focused XSS research;
   return any missing *general WAF* mechanism to `waf`'s focused-research
   branch. Distinguish source-reported possibilities from this target's facts.
3. **If yes:** Use `xss-payload-engineering` to compose a context-matched
   candidate from surviving grammar and an evidenced stage difference. Its
   `skills/xss-payload-engineering/references/parser-stage-character-variants.md`
   explains character/encoding prerequisites (load with `skill_view`). Return
   the candidate and one negative control to `waf` for a controlled comparison;
   do not turn tool-generated strings into a live sweep.
4. **Compare four gates:** (a) changed representation passes the same control,
   (b) intended value reaches the origin or client source, (c) it reaches the
   claimed executable sink after transformations, and (d) it executes in the
   stated browser/consumer under delivered CSP. A 200 or reflected string does
   not establish later gates. Separately ask whether the *victim's actual request
   and delivery path* can carry the representation; a tester-chosen transport
   may support only self-only execution. The parent XSS lane owns later-consumer
   and cross-user classification, not this overlay or the WAF counter.
5. **Return evidence:** Name the first failed gate and remaining uncertainty.
   Exact probes belong in the XSS lane's Attempts writer; stable target facts
   and sanitized evidence pointers in MapStore; reviewed portable mechanisms
   in ResearchMap under `xss-technology-research`'s admission rule. Keep
   untested ideas as hypotheses; never auto-promote a search hit or a
   site-specific payload to a portable card.

## Pitfalls and verification

- An encoded delimiter matters only if a later decoder produces syntax before
  an executable parser; an HTML entity in plain text does not itself create a
  tag in the same parse. A vendor-labelled retry is not a browser result.
- Body charset, parameter shape, and content-type changes matter only where the
  origin accepts them **and** the claimed victim can make that same request;
  shared WAF questions belong in `waf`, browser interpretation here.
- A currently valid vendor card may not match a different deployment's rules,
  exceptions, or version. Unknown WAFs follow the same measured loop.
- Complete this overlay with a compact packet: baseline/block signature,
  control confidence, app/card/research sources, sufficiency thesis, tested
  mutation and negative control, four gate results, victim-path question,
  residual uncertainty, and Attempts/MapStore pointers. A browser execution
  proof belongs to the XSS lane, not the interceptor counter.
