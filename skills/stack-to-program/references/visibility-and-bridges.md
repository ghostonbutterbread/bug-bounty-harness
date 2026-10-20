# Visibility and bridge guide

**Status:** active specialist reference; **owner:** `stack-to-program`; **canonical path:** this file; **supersedes:** none. This guide supports public-source candidate discovery only. The entry skill owns directory joins and live-testing boundaries.

## Choose the shortest justified route

| Visibility | Recognition signal | Public-first search | What remains unknown |
| --- | --- | --- | --- |
| Direct/observable | Component name or product/version appears in indexed headers, HTML, JS, protocol banners, published server metadata, or vendor-operated docs | Query established public technology indexes for the exact product/version, then attribute the domain and verify program association | Whether the index is current, the affected route is reachable, the actual build is patched, the asset is in scope |
| Composition/private | Native executable, library, container package, plugin, or delegate ordinarily invisible in network fingerprints | Advisory → caller/wrapper → exact product integration and feature → vendor-owned source/docs/manifests → company/program join | Whether optional components are installed or enabled, which feature invokes them, production build/configuration |
| Mixed | A visible product calls an unseen backend component | Use public index for the visible product **and** independent product-specific evidence for the private edge | The index cannot prove the backend dependency; the dependency cannot prove a particular indexed host uses it |

Do not make private dependency tracing a mandatory detour for a directly indexed component when the question concerns that visible component. Conversely, an HTTP frontend fingerprint cannot establish an invisible worker binary. A version from a vendor's source tree describes a source revision; an indexed banner is an observation of a reported public endpoint at a point in time; neither alone establishes the production execution path relevant to a CVE.

## Expand a private component outwards

Build a *conditional* graph rather than the claim “image processing implies Ghostscript”:

```text
advisory/component + affected behavior
  → direct caller / optional delegate / transitive package
  → accepted format or workflow that invokes it
  → named product integration in attributable public source/docs
  → program/company association
  → selected-program feature question (NOT a proven deployment)
```

Start at vendor advisories, package/dependency registries, reverse dependencies, and documented APIs. Follow edge direction carefully: library `A` can use `B` in one format handler while another handler uses a substitute; packaging `B` may be for tests, build, CLI administration, or an optional plugin. Prefer an attributable product implementation over generic feature similarity. Generate several distinct feature archetypes where the mechanism warrants them (e.g., EPS thumbnailing, document preflight, office preview, OCR, printing) rather than one global “uploads images” label. For every edge, record the source revision or date, role (required/optional/test/build), feature and format, and alternative implementation. An alternate implementation is a path-specific contradiction, not a blanket negative on a vendor.

## Evidence ladder and ranking

- **Direct product evidence:** vendor-owned source, install manifest, or advisory ties the component to a named product and feature. The existing CLI label may be `source-derived` or `disclosure`; production use/version remains unverified.
- **Public artifact/index observation:** an attributable, already-indexed banner, error, or generated file references the component. The CLI label may be `artifact`; attribution, recency, and endpoint role still matter.
- **Documented optional bridge:** upstream wrapper documentation says the caller *can* invoke the component for a format or mode. This proves the bridge exists in that wrapper, not that a particular product uses it; pair it with product-specific evidence before treating it as a corroborated product candidate.
- **Feature archetype:** product docs advertise a relevant input-to-transformation behavior but not the dependency. The CLI label is `feature-inferred`; keep it hypothesis-only. A generic image/PDF feature is weaker than documentation of a specific format and server-side transform.
- **Conflict/unknown:** an alternate handler for the same path, ambiguous ownership, unknown version, or an unavailable source gets `contradicted` or `unknown` as appropriate. The CLI places negative-only rows in `review_only`; mixed rows need manual adjudication, not numeric certainty.

The CLI accepts **one label per evidence row** and does not encode the full graph. Keep edge roles, precise quotes/links, alternate routes, query receipts, and version uncertainty in the accompanying human evidence packet; do not invent schema fields or collapse conditional bridges into a positive product assertion. The current collector is manual and non-exhaustive.

## Public-program enrichment and the handoff

Intersect product/company evidence with public directories using explicit identity rather than repo-owner or substring guesses. Verify current payment and rules on the program's first-party page, then inspect published program scope and product/API/help documentation for relevant features and competing flows. This is still public material: **no requests to the candidate application, even for a single version check, before the selected-program policy and scope gates**. Prefer to hand off a ranked set of different plausible consumers rather than one unconstrained program-wide scan. After selection, authorized recon can expand those surfaces as evidence warrants; absence of one bridge does not end the hunt if another path remains plausible.

Example handoff question: “Published docs describe server-side EPS thumbnail rendering; does an authorized, in-scope upload path actually decode that format through the named converter, and if so which patched build is running?” Keep the answer `unknown` until target-side evidence establishes it.
