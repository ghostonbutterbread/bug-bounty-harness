# XSS Continuation Dimensions

Load this reference from the XSS router when deciding whether a vector is
`exhausted`, or when a defense hit is about to end work on a vector that still
has a plausible executable consumer.

The router owns pressure state. `xss-payload-engineering` owns payload families
and character/parser variants. This reference owns only the **non-payload axes**
a vector can still be varied along, so that an exhaustion claim can be checked
by a reader instead of taken on trust.

## Why this exists

A first attempt stopped by a *soft* boundary — output encoding, a character
filter, a sanitizer, a WAF, an inert render, or no reflection — does not alone
establish exhaustion. The router directs pressure on warm vectors; this
reference distinguishes "I varied the available axes and the boundary held"
from "I tried one thing."

## The axes

A soft boundary observed on one axis says nothing about the others. When the
next axis is cheap and in-scope, varying it is ordinary work.

| Axis | Vary |
| --- | --- |
| Input location | Query, body, path segment, header, cookie, fragment, stored object field, filename, uploaded content. |
| Request shape | Method, duplicate/array/nested parameter notation, content type, parameter precedence, GET-shaped mutation, method override. |
| Representation | Encoding and decode stages — delegate the specifics to `xss-payload-engineering`. |
| Auth state | Unauthenticated, owned authenticated, second owned account, elevated role, cross-principal writer. The same field often has a different escaping path per role. |
| Consumer | The same stored value in a different renderer: list vs detail, email, export, PDF, notification, admin view, feed, mobile, embed, print. |
| Producer | A different write path to the same field — see `source-acquisition.md`. |
| Delivery context | Raw HTTP vs real browser, SSR vs hydrated, cold vs warm cache, edge vs origin, direct vs SPA-routed navigation. |
| Defense boundary | Edge filter vs application filter vs renderer escaping vs CSP. Determine *which* layer blocked before concluding the vector is defended. |

Attributing a block to the wrong layer is the common error: a payload-dependent
edge 403 is not evidence about the application's escaping, and an inert render
is not evidence about a sibling consumer. `waf-live-policy` and
`http-status-live-policy` own that attribution.

## Recording an exhaustion claim

`exhausted` is a claim about a path, so make it a claim a reader can falsify.
When recording it, name the axes you varied, the boundary that held, and the
layer that enforced it — and name the axes you did not vary and why, so the
residual is explicit rather than silently lost.

An axis left unvaried because of a missing owned account, role, object, session,
or fixture is an operational blocker, not exhaustion;
`general-security-testing-policy/references/testing-posture.md` governs that
distinction and `account-testing-policy` owns obtaining the artifact. An axis left unvaried because the layer that enforced the boundary
makes it irrelevant is a sound closure — state that reasoning.
