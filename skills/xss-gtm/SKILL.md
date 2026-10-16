---
name: xss-gtm
description: Use a preconfigured GTM container as an XSS proof fixture.
---

# XSS GTM fixture

Use this after `xss` when an authorized XSS path can select a GTM container ID
or load a GTM script. This is a reusable **payload fixture**, not a separate
XSS class or an instruction to manage Google Tag Manager. The selected
`reflected-xss`, `stored-xss`, `dom-xss`, or `blind-xss` lane still owns delivery
and browser proof.

## Fixture

Ryushe supplied this container as already carrying a basic XSS payload:

```text
GTM-NRM7SMTK
https://www.googletagmanager.com/gtm.js?id=GTM-NRM7SMTK
```

Use the ID where an input selects a container; use the script URL where the
observed sink permits an external script source. Adapt syntax to the actual
HTML/JavaScript context. Do not modify the container, create tags, or require
GTM account/API access. Its exact current tag behavior has not been verified by
this skill and may change.

## When to try it

First establish a plausible attacker-controlled source-to-script path and the
effective browser/CSP boundary. The site's existing fixed GTM tag is not itself
an injection path. If GTM is blocked, the container does not fire, or the
injected value never reaches an executable context, record that boundary and
continue the owning XSS lane rather than claiming a bypass.

## JavaScript Lens

In a bundle or browser trace, look for user-influenced values entering a GTM
loader's container ID or script URL. Confirm the actual writer, renderer, and
policy in the scoped page; a string match for `gtm.js` is only a lead.

## Verification

On the authorized test page, correlate the injected source with the GTM script
request **and** the actual browser effect of the preconfigured payload. Record
the executing page/origin and delivery path. A network load, investigator-only
preview, or another container's execution alone is not confirmed XSS. Follow
the owning XSS lane's live-testing, attempt-recording, cleanup, and proof rules.
