# ATO chain composition — find the missing edge

**Status:** active optional reference. **Owner:** `/ato`. **Canonical path:** `skills/ato/references/chain-composition.md`. **Supersedes:** none. Load when an observed account/security change or credential exposure is real but its route to unauthorized control is unclear. This is a reasoning bridge, not a vulnerability checklist or a substitute for the selected specialist. For a flow map or handoff packet, use `references/flow-handoff.md` instead.

## Inventory pieces, not a required sequence

A chain can start from any observed piece and need not contain all of these. Do not infer a missing edge from the existence of its neighbors.

- **Entry:** What can the attacker control, and how would the owned comparison account encounter it? A URL, message, account, inbox, IdP, subdomain, or saved value is not automatically a victim delivery path.
- **Execution or exposure:** Does a browser, app, IdP, mailbox, or later consumer actually cross the relevant trust boundary? Identify the exact origin, recipient, device, and interaction condition.
- **Authority:** What credential or proof accompanies the operation—cookie, bearer, current session, CSRF token, reset code, IdP assertion, factor, or approved role? Which party can obtain or cause its use? A browser does not attach a script-held bearer merely because CORS allows an origin.
- **State change:** Which account and pending transaction does the server finally update? Which verifier was required, and was it actually checked on this route?
- **Control and proof:** Can the newly controlled login/recovery method authenticate as the *other owned account* or make the protected security change? Read back the resulting server-side account, factor, link, role, and notifications. An accepted request or delivered email alone is not durable takeover.

## Work backward from the stalled primitive

1. State the **proved** piece and the exact missing edge in one sentence. Keep assumptions separate from observations. For example: “An owned bearer can change the primary recovery address; no victim-origin delivery or final login is shown.”
2. Ask what must be true for the missing edge: required method and headers, origin and preflight, actual browser credential source, account/recipient/transaction binding, or the usable lifetime of a handed-off credential. Inspect the observed app path before selecting a technique. An authenticated command-line replay is not proof a foreign-origin browser can make that request.
3. Select one plausible bridge with a smallest safe discriminator using owned identities. If it fails, record **which edge** failed and return to the remaining pieces; do not call the entire ATO surface exhausted or assert an alternative bridge exists. If no observed bridge remains, retain the primitive as a bounded lead and stop rather than inventing delivery.
4. Follow the resulting authority through the final change or login only as far as needed for minimum safe proof. Revisit independent observed flows without repeatedly escalating a proven path.

## Conditional bridge questions and owners

- **Cross-site send (`/csrf`):** Can a real foreign-origin browser issue this method/body with authority the server accepts? HTML forms cannot directly issue PUT; a non-safelisted method or `Authorization` header requires a successful CORS preflight. Cookie presence and SameSite behavior must be observed in the relevant real session. A raw replay with a manually supplied bearer proves none of this.[1][2]
- **Cross-origin read or preflight permission (`/headers`, `/csrf`):** Does the target grant the *actual attacking origin* credentialed access to a sensitive response or the required preflighted method/headers? CORS governs browser response access and non-simple request permission; it neither supplies a bearer token nor replaces CSRF protection. A response to one untrusted origin does not rule out an observed trusted origin or a different route.[1]
- **Trusted-origin execution (`/xss`, the relevant XSS specialist, `/dom-xss`):** Does script execute in the origin that can use the protected request path or reach its credential? Sibling subdomains are distinct origins. Show token availability, a permitted cross-origin route, or the app's own request machinery before claiming the script can perform the change.[3]
- **Request deputy (`/dom-xss`, `/headers`, or the relevant AI/tool-abuse specialist):** If an observed `postMessage`, embedded widget, service worker, or integration handler can be attacker-influenced, does a trusted principal actually construct and send the protected request? A listener or message acceptance without a security-state effect is not proof.
- **Credential handoff (`/password-reset`, `references/federation.md`, `references/factors-sessions.md`):** Does an observed redirect, deep link, login/transfer link, cookie scope, or callback deliver a *usable* credential to a party lacking it? Prove intended recipient, origin/device, purpose, expiry, and final redemption on owned accounts; an open redirect or claimed subdomain alone is insufficient.
- **Identity and pending-state binding (`references/identity-lifecycle.md`, `references/federation.md`, `references/organization-identity.md`; `/access-control`, `/idor`, `/race`, or `/bypass` for mechanism):** Do actor, target account, proof recipient, transaction, and final principal remain bound across alternate clients, parsers, retries, or concurrent changes? A mismatch matters only when it changes an owned account's authority, recovery path, factor, or membership contrary to policy.

These examples are **non-exhaustive**. Choose a route from current signals, not from a duty to exercise every bullet. A missing `state`, writable-looking field, XSS on a sibling host, or successful cross-site response is a lead until its actual authority and final binding are established.

## Bounded example

Suppose an owned bearer-only profile endpoint can switch a primary address only to an **already confirmed** address, while adding a new address leaves it unconfirmed. First separate the proved security change from the proposed new-inbox confirmation, victim delivery, and reset/login steps. If an arbitrary-origin PUT preflight is denied, direct cross-origin fetch is closed for that tested origin/method/header combination; do not infer that all browser routes or all origins were tested. If guessed token-as-cookie names fail, the genuine browser auth model is still unknown. A same-site XSS does not automatically cross to the API's origin. Investigate only observed bridges with owned fixtures, then require final read-back before claiming the larger chain.

The general `/ato` stop conditions and evidence rules apply. Do not solicit non-owned security mail, brute-force codes, attempt staff-facing impersonation, or turn a speculative chain into a reported takeover.

## Sources

[1] https://portswigger.net/web-security/cors/access-control-allow-origin
[2] https://portswigger.net/web-security/csrf
[3] https://portswigger.net/web-security/cors/same-origin-policy
