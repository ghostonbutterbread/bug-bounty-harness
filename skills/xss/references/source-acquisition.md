# XSS Source Acquisition and Sink-Census Decisions

Load this reference from the XSS router when a confirmed sink has no currently
reachable controlled source, a sink census needs prioritization, or a sanitizer
or impact clue could change that ranking. The router owns the missing-fixture /
server-constrained / no-source decision; do not reclassify a missing fixture as
an exhausted or false-positive lane here.

## Prioritize a path, not a sink count

1. **Source reachability:** identify an attacker-writable field, parameter,
   header, stored object, or later consumer that could feed the observed sink.
   If it requires a normal owned artifact or account, name and create that
   fixture under `account-testing-policy` and inherited safety gates.
2. **Consumer and defense posture:** compare the actual renderer and CSP;
   `unsafe-inline` or absent CSP may change viability, while a nonce-based
   policy can constrain an otherwise promising path. Look for email, export,
   metadata, share, or other consumers that might render the same stored value
   differently.
3. **Sink count:** use only as a tiebreaker among paths with comparable source
   reachability and consumer behavior.

A static inventory discovers candidates but does not prove that a user-controlled
source reaches them. Preserve the specific source-to-sink question and a
reopening condition instead of repeating a larger census.

## Sanitizer evidence

Do not infer the absence of sanitization from a bundle name search: server-side
sanitization is invisible in the client bundle, and minified client libraries
may not retain recognizable names. If sanitizer behavior is observed, examine
its configuration and actual output—allowed tags/attributes/schemes,
namespace handling, trust wrappers, decode and reparse stages—rather than
ranking solely by whether a library name appears. Route a concrete fingerprint
to `xss-technology-research`; route context-matched mutation to
`xss-payload-engineering`. Neither a sanitizer hit nor one rejected payload
closes a plausible source-to-consumer path.

## Impact amplifiers

Before deprioritizing an otherwise reachable path on a low-tier host, check
whether a **confirmed** same-origin-family primitive changes its impact. For
example, a proven cross-origin credentialed read might amplify a browser
execution path. Use a bounded ledger query for the concrete origin family;
route severity judgment to `impact-fit-policy`. Do not assume an amplifier
merely from a report title or use it to expand scope.

## When to rerun a census

A sink census is a ranking instrument, not proof of coverage. Re-run when the
corpus or application changes materially (new hosts, bundles, deployments, or
consumers), or when a concrete observed source could change the ranking. Do not
rerun an unchanged corpus merely for a fresher list. Continue to inspect
stack-specific render paths and track unexamined source-to-sink questions.

## Finding a writer for an observed sink

When a render sink is observed but no reachable attacker-controlled source is
yet known, a negative needs a specific broken link. Use this method inventory
to choose a relevant check, not as a sequence to run.

A sink has a writer unless you can state which link cannot exist. Before
recording a no-source negative, consider which of these you have actually
looked at for *this* consumer:

| Where writers hide | What to look for |
| --- | --- |
| Same field, different producer | The API/GraphQL/mobile/partner/import path that writes the field the UI validates client-side. The web form's regex is rarely the server's. |
| Request-shape variants | POST body vs query precedence, duplicate params, array/nested notation, JSON vs form encoding, `PUT`/`PATCH`, method override, GET-shaped mutations. |
| Undeclared parameters | Names present in bundles/specs/sourcemaps but absent from live traffic; see the stack-selection table below. |
| Adjacent object fields | Sibling attributes on the same object that the renderer concatenates (title vs subtitle, name vs description, label vs tooltip, alt vs caption). |
| Server-returned values the client re-renders | Error `message`/`params`, validation echoes, i18n interpolation values, autocomplete/suggestion payloads, feature-flag and bootstrap config. Interpolation libraries frequently do not escape. |
| Cross-principal writers | A field another account, org member, invited user, or integration can set on an object you render. This is usually what converts self-XSS into a finding. |
| Import and sync paths | CSV/JSON/XML import, webhook ingest, CMS/preview, repo contribution, migration, bulk edit, third-party connector. |
| Metadata and derived text | Filename, EXIF, archive entry name, URL slug, redirect target, OAuth client/app name, SAML attributes. |
| Lifecycle-delayed consumers | The same stored value in email, export, PDF, feed, notification, admin view, or receipt — a different renderer with a different escaping posture. |

When the writer exists but you lack the account, role, object, invite, or
session to use it, that is an operational blocker: `account-testing-policy` owns
creating the normal owned artifact, and
`general-security-testing-policy/references/testing-posture.md` already governs
that this is not closure. Name the exact missing artifact and the wake
condition. An observed sink parked on a missing writer fixture is unfinished
work with a known cost, not a negative — track it where it will be drained
rather than only describing it in a map entry.

## Choosing a hidden-parameter method by stack

Differential parameter discovery infers a parameter from a response delta. That
inference fails wherever the framework echoes unknown input, so tool choice
depends on the observed stack. A hydration format that serializes arbitrary
query keys and values (such as RSC flight) can saturate the anomaly baseline:
response-delta tools may report false positives or miss meaningful names.

| Observed stack | Preferred method |
| --- | --- |
| Classic server-rendered app (JSP/PHP/.NET/WCS/Hybris/ServiceStack) | Differential discovery (Arjun/`x8`-style) works; reflection and length deltas are meaningful. |
| SPA that echoes input into a hydration payload (Next.js RSC, Nuxt, `window.__*`) | Do not trust response-delta tooling. Mine `searchParams.get`/`getParameter`/`router.query`/`useSearchParams` and destructured prop names from bundles and sourcemaps. |
| API/GraphQL | Read the schema, spec, or client query set; introspection and operation names beat guessing. Compare field sets across clients (web vs mobile vs partner). |
| Any stack | Sourcemaps and legacy/microfrontend bundles frequently retain parameter names the current UI no longer sends. |

Confirm every discovered name with a controlled canary before building payloads
on it: a tool's parameter claim is a lead, not evidence of an accepted input.
Route candidate names into `parameter-mining` and the fuzzing lanes rather than
keeping them in one run's notes.
