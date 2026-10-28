---
name: cloudflare-xss
description: "Use for Cloudflare-specific XSS ideas and research."
---

# Cloudflare XSS Knowledge

- **What:** One knowledge shelf for Cloudflare-related XSS mechanisms and sources.
- **When:** Investigating XSS on a site that uses Cloudflare; no WAF block is needed.
- **How:** Follow the ideas matching the observed feature or transform, not a required checklist.

Cloudflare presence is a reason to consult this knowledge, not evidence that a
feature is enabled or vulnerable. These are **source-reported** mechanisms,
not a claim that current deployments are vulnerable. Some introduce a same-origin
source or gadget rather than bypassing a WAF. Keep the selected XSS lane's live
boundaries, browser proof, and cleanup; this skill adds ideas, not another
execution procedure. A missing feeder or consumer remains a chain question.

## Image Transformations: source, sanitizer, and cached document

[Cache Me If You Can](https://www.slcyber.io/research/cache-me-if-you-can-xss-in-cloudflares-cdn-cgi-image)
(2026-10-28) combines three independent pieces at `/cdn-cgi/image/`. None alone
establishes the complete chain; the write-up does not establish current patch
status for a target or installed browser.

**Source restriction and redirects.** Image Transformations must be enabled.
[Cloudflare's source-origin docs](https://developers.cloudflare.com/images/transform-images/sources/)
say the initial URL is checked, then redirects are followed even outside the
zone. An allowed source with a redirect can therefore feed controlled content.
The article additionally reports an Access `/cdn-cgi/access/logout?returnTo=...`
redirect chain when Access was enabled somewhere in the zone. Its particular
Cloudflare-hosted redirect is historical research evidence, not a reusable live
service or permission to probe unrelated Cloudflare infrastructure.

**Compare:** Trace an owned allowed source, a directly disallowed source, and a
controlled redirect's final response. A rejected redirect or unmodifiable
source breaks that feeder, not every source path. The older
[HackerNotes image gadget](https://blog.criticalthinkingpodcast.io/p/0-days-htmx-ss-with-mathias)
reports `onerror=redirect` with a zone-bound destination; do not mistake it for
an unrestricted redirect or the newer Access chain.

**SVG sanitizer serialization.** In the reported `svg-hush`/`xml-rs` path,
ordinary attributes were escaped, but namespace URI metadata was serialized
without equivalent escaping after validation. That let emitted XML contain new
markup. The portable question is whether *every serializer output channel*,
including namespace declarations, preserves the sanitizer's safety assumptions.
See the article's pinned implementation links; a library name alone is not a
version match.

**Compare:** Inspect the accepted SVG and exact emitted bytes against a benign
namespace control, then their document interpretation. Correctly escaped output
falsifies this serialization path. An image element is not equivalent to a
navigated SVG document; establish the actual consumer before judging execution.

**Cache/header reinterpretation.** The source response's forwarded
`Cache-Control: no-cache="Content-Security-Policy"` could omit the CSP header
from Chromium's reused HTTP cache entry while the initial response still had
it. The article uses an opener-related history-navigation flow to avoid
BFCache (a document/heap snapshot) and reuse the HTTP cache instead. This is a
browser cache mechanism, not CDN cache poisoning. Browser version, cacheability,
opener/COOP behavior, and actual navigation determine applicability.

**Compare:** Observe initial load and history return with ordinary versus
field-qualified cache directives, recording effective policy and cache source.
A network refetch or BFCache restoration does not demonstrate header loss. A
retained enforcing CSP, including an applicable meta policy, may still block
execution. [RFC 9111's qualified no-cache semantics](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4)
and the [spanote cache research](https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote)
explain the cache distinction; neither substitutes for browser evidence.

The same article extends the idea beyond Cloudflare: omitting `Content-Type`
can enable MIME sniffing and an XML-to-HTML parser change (Netlify's reported
SVG processing-instruction differential); signed storage response-header
overrides can supply type/cache control. These need their own header forwarding,
body, nosniff, disposition, signature, and executing origin conditions. Do not
assume Cloudflare accepts another optimizer's SVG polyglot.

## Response rewriting after inspection

**Signal:** Email obfuscation or another edge feature changes origin HTML before
the browser sees it. [When security features collide](https://portswigger.net/research/when-security-features-collide)
(2017) showed email rewriting repairing malformed syntax after request
inspection and creating parser differentials. Its browser XSS-filter claims are
historical; the useful idea is to compare what the filter sees with what the
response rewriter emits.

**Compare:** Use feature-triggering versus non-triggering markup and compare
request representation, delivered HTML, and resulting DOM. If the relevant
rewrite does not happen or remains inert in this consumer, that mechanism is
not shown. Passing the WAF is separate from browser execution.

## Managed scripts, DOM gadgets, and fetched error bodies

**Signal:** A policy trusts same-origin Cloudflare-managed resources, or app code
fetches a controllable path and inserts the response as HTML. Historical
[/cdn-cgi/nexp research](https://x.com/kinugawamasato/status/893404078365069312)
(2017) involved optional Rocket Loader and `unsafe-eval` conditions;
[/cdn-cgi/scripts research](https://x.com/kinugawamasato/status/1414648695904083988)
(2021; [original PoC](https://l0.cm/cf_cspbypass.html)) combined managed scripts,
translation handling, and controlled DOM structure. Neither implies those
resources or gadgets remain available today.

[Mizu's CSPT → innerHTML lead](https://x.com/kevin_mizu/status/2074463929401516413)
(2026) uses an image-transform response as markup for a later DOM consumer.
Here CSPT means client-side path traversal: source URL control is the feeder,
not execution. Direct navigation and a fetched error body inserted into
`innerHTML` are distinct paths; response status or reflection alone settles
neither.

**Compare:** Trace the actual loaded code or fetch caller, controlled value,
returned representation, and interpreter against renamed DOM/non-HTML controls.
A missing script, safe text insertion, unreachable sink, or incompatible browser
breaks that edge. Existing trusted code and the delivered CSP decide whether a
gadget can execute; a Cloudflare banner does not.

## Access / MCP: second-order consumers and impact

[Cloudflare MCP Portal XSS to account takeover](https://kazama.in/mcp-server-portal-xss-to-ato/)
(2025) reports registered redirect values reaching a later JavaScript navigation
sink, patch bypasses, and app-session versus organization-session escalation.
The author reports the issues fixed. Use it to ask where stored URL/config
values are later interpreted and what trust boundary a *proven* XSS reaches;
it is not a generic takeover option on Cloudflare-fronted sites.

**Compare:** Follow an owned registration's harmless redirect through the actual
later consumer and scheme/escaping checks. Server acceptance alone proves no
execution. Absence of MCP Portal removes this particular product path, not
other Cloudflare XSS ideas. Session invalidation and token-exchange actions
remain subject to the existing owned-account and impact-testing policies.

## JavaScript Lens

Use browser-observed `/cdn-cgi/` scripts, email-rewrite markers, image URL
builders, fetch-to-HTML call sites, and redirect consumers to select these ideas.
Trace caller → controlled value → response/transform → browser sink with `js`
and the owning XSS lane; do not infer a taint path from matching names. Research
can guide source-first or sink-first exploration without making a full JS
inventory a prerequisite.

Keep target observations in MapStore, exact probes in canonical Attempts, and
reviewed portable mechanisms in ResearchMap through `xss-technology-research`.
The links here are source leads, not a second target-notes store.

## Related skills

- If selecting or proving a source-to-consumer path, load `xss` and its matching lane.
- If filtering is the actual obstacle, load `waf` and `xss-waf-evasion`.
- If a delivered CSP is the obstacle, load `csp-bypass`.
- If version/configuration or source details change the next idea, load `xss-technology-research`.
- If confirmed XSS exposes a further trust boundary, load `impact-escalation`.
