# XSS Source Acquisition and Sink-Census Decisions

Load this reference from the XSS router when a confirmed sink has no currently
reachable controlled source, a sink census needs coverage or prioritization,
or a sanitizer or impact clue could change that ranking. The router owns the
missing-fixture / server-constrained / no-source decision; do not reclassify a
missing fixture as an exhausted or false-positive lane here.

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

## Pair input locations with consumers

If a route cluster's missing input or consumer is being investigated through
JS, inspect both ends without imposing a source-first or sink-first order.
Reuse current JS inventory where relevant; compare it with scripts actually
loaded on the selected flow before deciding what needs fetching. For a
browser-mediated JS question, load `browser-session-policy` and `chromium-test`
to navigate the authorized app and trigger relevant interactions. Inspect
Network requests and loaded scripts, Sources/call stacks and DOM/form/hydration
state (or equivalent observations); a lazy chunk, hidden field or client-side
request builder may appear only after a route, click, form, or state transition.
Retain page/flow, JS URL, initiator, and associated request/field provenance.
When new JS is needed, feed scoped observed JS URLs to `js` → `js-pull`
(`bbh agents/js_analyzer.py inventory <program> --input <scoped-js-url-list>
--target-host <in-scope-host>`); use `js-hunt` when selected functions need
tracing. `inventory --page` fetches HTML script URLs and bounded inline scripts
from an HTTP page; it does **not** drive the browser or capture lazy-loaded chunks.
The analyzer's `--input` list accepts `.js`, `.mjs`, `.cjs`, and extensionless
URLs directly. For a browser-loaded `chunk.php` (or another non-JS suffix),
also supply `--provenance-input <observed-scripts.jsonl>` with a row keyed by
the **exact JS URL**: `js_url`, loading `page_url`, saved `proxy_request_id`,
`initiator` (`script` or `parser`), a 2xx `status`, and JavaScript
`content_type`; `method` must be GET if present. Only scoped URLs in the
explicit `--input` list are considered, and the fetched or cached response
must itself have a 2xx status and JavaScript MIME type before inventory;
`--target-host` is required for this non-JS-suffix exception.
An HTML login/error response is skipped, not a zero-hit script. Preserve the
browser observation as a lead if an unauthenticated refetch cannot reproduce
it; never relabel an unscanned response as inventoried. An HTML `<script src>`
discovered by `--page` may enter regardless of suffix, but `--page` cannot
recover a chunk loaded only after interaction. Inspect its returned status,
MIME type and body separately; an HTML `<script src>` alone does not prove
that the script URL served executable JavaScript.
Do not conclude that one initial load represents the application.

Keep three evidence levels distinct: an **inventoried script** may be archived
or never loaded on this flow; a **browser-loaded script** establishes asset
reachability on that observed route; an **observed input-to-renderer path**
additionally needs the relevant field, transform and consumer correlated in
runtime evidence. DevTools breakpoints and task-MITM request shapes can resolve
the latter without turning a static signature into execution proof.

The analyzer invokes `agents/xss_source_sites.py` and
`agents/xss_sink_sites.py` on retained JS and packetized source-map modules;
neither module independently discovers live routes or proves attacker control.
`metadata.jsonl` has per-bundle `source_sites`, `sink_sites`, ordinary
`params`, and page/provenance pointers; `source_map_modules.jsonl` has named
sites in retained original modules. A zero or capped hit count is not coverage:
check `source_sites_truncated`, `sink_sites_truncated`, and the manifest's
source/sink capped-artifact counts. Also inspect each source-map module's
`packet_status`: `truncated_by_budget` and other unpacketized modules have no
site list to inspect, even when their per-site truncation flag is false.
An older inventory predating the source pass must be reanalyzed before using
it as a named-source denominator.
`source_sites` are bounded named getter/read sites (query, route, form, cookie,
storage and DOM data, plus unnamed source hints), **not** all accepted request
fields or confirmed attacker-writable inputs. Outbound form/query writes can
appear as `interesting_keys` or other request vocabulary without appearing in
`source_sites`; correlate them with actual browser/proxy requests and
`parameter-mining` rather than treating zero named reads as no parameters.

Use the observed stack to look **beyond** the signature list: inspect the
actual framework raw-HTML/template/trust APIs, server-rendered templates,
custom render wrappers, URL/script loaders, and the stack's query/route/form/
API request builders. `dom-xss` owns browser source/sink tracing and its
framework map; `xss-technology-research` helps when a concrete renderer or
sanitizer fingerprint changes the next question. A static match in an unloaded
bundle is a seed; a browser breakpoint, populated field, or emitted request
adds reachability evidence, but neither alone proves a controllable
source-to-executable-consumer path.

Resolve the aggregate with
`bbh scripts/recon_bus.py query <program> --artifact params --format path`;
inspect its shape before use. Some `params.txt` files contain parameterized
URLs (preserve scoped host, route, and key); others contain **name-only** entries
(candidate vocabulary, no route or accepted-input claim). Historical or
third-party URLs, generated fuzz names, and tool guesses do not prove a live
source. Correlate JS names with the relevant route/request builder and
parameter artifacts by provenance, not a global string intersection. Follow
stored/API response fields back to their writable endpoint or object field;
a query parameter is only one possible writer.

When source-attributed fields or writers are missing, `parameter-mining` can
combine browser requests, JS inventory, proxy evidence and aggregate recon.
A large `params.txt` may still lack body/GraphQL/form fields or route links;
work relevant unreviewed candidates when present. For a broader pivot, load
`surface-expansion` rather than treating an archive size or tool run as an
exhaustion threshold. Before a scoped negative, compare mapped XSS
route/action/input/consumer questions with the Coverage brief and JS/parameter
inventories; distinguish unexamined paths, missing chunks, and blocked owned
prerequisites. Record the remaining frontier and wake condition instead of
calling the whole program exhausted.

Diff the route-and-field candidates against prior parameter-specific test
coverage (`url-ingest`) before selecting untested named inputs. Use an inert
canary on the actual name and observe the response/browser consumer. A shared
bundle, common name, or short source-to-sink distance is **not a taint trace**.
If the path is still unclear, retain its missing writer/consumer edge and
trigger; do not mark the sink group or route exhausted. A scoped exhaustion
claim names the tested ingress paths and render consumers and notes missing,
truncated, legacy, or source-map-only inputs rather than dividing a raw source
count by a raw sink count. A strong current path does not wait for a full census.

## Reconcile sink groups without collapsing input paths

Group repeated sites when they share a downstream consumer or rendering helper;
this saves repeated analysis of that piece, not testing of every route into it.
Keep each distinct input/entry route as a separate path through its request
filter, validation, encoding, storage and decode stages. Two writers of the same
backend field may have different transforms or WAF treatment; the same value in
a page and an email may have different renderers or CSP. A group-level negative
does not close an untested ingress or consumer.

For a distinct path, retain the input route and control, meaningful transforms,
consumer/render context, evidence, and disposition: connected, constrained or
fixed, not live in the tested context, missing a source/prerequisite, or
unexamined. Scope each negative to the route, source, and consumer tested.
At a meaningful handoff, distinguish raw inventory hits from reviewed
consumer groups and ingress paths, and name unexamined paths and inventory
limits (including capped or missing assets). This is coverage accounting, not
a fixed percentage, new Attempt shape, or demand to payload-test every hit.

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
