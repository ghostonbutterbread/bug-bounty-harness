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

## Entry packet

Use an inert marker and a clean/blocked differential to assemble only what is
observed; leave unknowns explicit:

```text
attacker-controlled source and request representation
plausible sink, HTML/attribute/URL/script/JSON/DOM grammar, later consumer
control location and evidence (edge, bot/rate, origin filter, sanitizer, unknown)
blocked and surviving primitives; exact bytes before/after known transforms
route, component, content type/charset, session, browser/CSP
who sends the request and who encounters the output
```

Do not confuse an origin reject-on-match filter with a sanitizer that rewrites
markup. Distinguish a vendor header from a matched rule and a temporary
challenge from a payload decision; compare with a green control. If the layer
is unclear, return to `waf` / `waf-live-policy` for classification rather than
inventing vendor behavior.

## Retrieval and sufficiency loop

1. **Query current app facts:** Once this surface is chosen, use `map-store`
   `app-facts`/`dedupe` for this URL, route, and defense. Query portable
   ResearchMap cards by observed WAF/control *plus* inspected component,
   decoder, renderer, or sink; read only matching cards. Vendor identity alone
   is not a card match. See `xss-technology-research` for the bounded research
   packet and reviewed card promotion; source leads live in
   `references/vendor-and-mechanism-sources.md`.
2. **Ask sufficiency:** Is there enough evidence to build a **plausible bypass
   of this blocker** that remains meaningful in the actual XSS consumer? Write
   one causal sentence: “control inspects representation A; origin or browser
   interprets B because stage C; the same victim-reachable flow can carry it.”
   Name a checkable precondition, expected negative control, and contrary
   observation. This is permission to *test a hypothesis*, never success proof.
3. **If no:** Research the concrete difference, not “vendor X bypasses.”
   Compare vendor/upstream documentation, implementation or rule version,
   parser standards, relevant papers, and the local ResearchMap; use the
   approved safe-fetch path. Distinguish source-reported behavior from observed
   target facts. If research still leaves no candidate, run the smallest
   distinct inert discriminator or preserve the missing prerequisite and return
   to the XSS lane; an empty search does not close the path.
4. **If yes:** Compose the smallest context-matched candidate from the
   surviving grammar and an observed stage difference. Keep the original
   blocked request, one changed causal feature, and a green/negative control.
   Use `xss-payload-engineering` for candidate queues and its
   `skills/xss-payload-engineering/references/parser-stage-character-variants.md`
   for encoding rules (load that skill-local reference with `skill_view`).
   Use `references/technique-questions.md` here to select an ingress/control
   question, not as a payload bank. If a tool emits many strings, reduce to
   distinct hypotheses before live use.
5. **Compare four gates:** (a) the changed representation passes the same
   control, (b) the intended value reaches the origin or client source, (c) it
   reaches the claimed executable sink after transformations, and (d) it
   executes in the stated browser/consumer under delivered CSP. A 200 or
   reflected string proves none of the later gates. Then separately ask whether
   the *victim's actual request and delivery path* can carry the representation;
   a tester-chosen transport may prove only a self-only primitive. The parent
   XSS lane owns classification of self-only, later-consumer and cross-user
   impact; do not rebuild that policy here.
6. **Learn and iterate:** If a gate fails, record the first divergence and
   choose another causal family only while the warm/hot path and inherited
   safety boundary justify it. Exact live probes use `attempt-recording-policy`
   and the XSS lane; stable target observations plus sanitized pointers go to
   MapStore. A reusable, source-cited mechanism becomes **one** ResearchMap
   card only after `xss-technology-research`'s admission review states its
   recognition signal, preconditions, smallest check, caveats, and status.
   Keep untested ideas in the current hypothesis; never auto-promote a search
   hit or a site-specific payload to a portable card.

## Pitfalls and verification

- An encoded delimiter matters only if a later decoder produces syntax before
  an executable parser; an HTML entity in plain text does not itself create a
  tag in the same parse. A vendor-labelled retry is not a browser result.
- Body charset, parameter shape, and content-type changes matter only where the
  origin accepts them **and** the claimed victim can make that same request.
- A currently valid vendor card may not match a different deployment's rules,
  exceptions, or version. Unknown WAFs follow the same measured loop.
- Complete this overlay with a compact packet: baseline/block signature,
  control confidence, app/card/research sources, sufficiency thesis, tested
  mutation and negative control, four gate results, victim-path question,
  residual uncertainty, and Attempts/MapStore pointers. A browser execution
  proof belongs to the XSS lane, not the interceptor counter.
