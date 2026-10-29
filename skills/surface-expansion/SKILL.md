---
name: surface-expansion
description: Use when a security hunt needs new in-scope surfaces. Compare adjacent consumers, inputs, client routes, and hosts without a mandatory sweep.
---

# Find New Surface

Use this as a **menu of directions**, not a startup sequence, tool quota, or
condition for testing a promising current path. Pick the next direction from
the missing link: source, writer, route, consumer, or different app context.
The selected vulnerability skill still owns proof and closure.

- **Another consumer:** Follow a controlled value into preview, notification,
  email, export, admin, search, mobile, or an asynchronous worker. A different
  renderer/parser or principal may change the result.
- **Another input:** Look at actual forms, hidden fields, request bodies,
  GraphQL variables, route/hash/query state, proxy-observed requests, and
  source-attributed parameter candidates. Load `parameter-mining` to combine
  relevant sources; `params.txt` size alone says nothing about accepted fields.
- **Another endpoint from JavaScript:** Reuse scoped JS bodies and source maps;
  inspect request builders and API client calls for route, method and field
  candidates. Load `js` and its `skills/js/references/analysis-lens.md` (from
  the BBH repository root) for the current
  question, or `jsluice` for *offline* local-file URL extraction; use `js-hunt`
  for an explicitly broader JS campaign. Correlate with browser requests and
  `api-surface-mapping` before treating a string as a reachable operation. Do
  not substitute a live Katana
  `-jc` crawl for offline extraction: that flag parses JS **and crawls** its
  discovered endpoints. If a locally installed Katana version exposes a
  verified extraction-only mode, its tool owner can use it on retained files;
  otherwise do not claim Katana can parse them without target traffic.
- **Another JavaScript:** A route transition, account state or interaction may
  load a new chunk or source map. Load `js` → `js-pull` for an inventory gap and
  keep page/flow provenance; absence of one script is not absence of all JS.
- **Another app area or scoped host:** Inspect unmapped navigation, roles,
  microfrontends, subdomains, or domains only within the published scope. Use
  `live-map`, `focused-recon`, and `api-surface-mapping` as relevant; similar
  hostnames are not automatic authorization.

At a pivot, compare candidates with already reviewed paths and their evidence;
select a distinct source→transform→consumer question rather than a larger
string list. Keep source-declared, historical, and freshly observed evidence
separate. Preserve the remaining gap and its reopening condition. A thin map
is a discovery lead, not proof of safety or a reason to stop a warm path.

## Related skills

- Missing or changed JS corpus → load `js` then `js-pull`.
- New fields or writers → load `parameter-mining`.
- API operation context → load `api-surface-mapping`.
- Live external tooling → load `bounty-tools` and the normal scope/rate chain.
