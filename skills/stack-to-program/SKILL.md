---
name: stack-to-program
description: "Use when starting from a CVE, named technology, library, or native converter to find candidate bounty programs through public evidence before choosing a target."
---

# Stack-to-program

Reverse the usual program-first search: start with a component, discover products that publicly document or disclose its use, then intersect those products with public bounty directories. This is **selection research**, not live reconnaissance, permission to test, or proof of vulnerability. Do not request candidate applications, enumerate their live hosts, upload files, create accounts, or probe conversion APIs in this lane. A directory's domains are owner hints, **not scope**.

When Ghostscript, Artifex, `gs`, or a Ghostscript CVE is named, also read [references/ghostscript.md](references/ghostscript.md). For an already-selected program, hand off to `general-security-testing-policy`, `program-testing-policy`, `/pullscope`, then the appropriate recon and technology-research skills. Without a stack criterion use `program-finder` directly.

## Decision flow

1. **Pin the advisory and time gate.** For a CVE, record its canonical advisory, affected package/product ranges, fixed versions, publication date, and the program's disclosure/patch-exclusion rules when later selected. An operator's “30-day timeline” is not a universal safe-harbor: calculate the relevant date from the actual advisory, distinguish publication from program-specific embargo or grace period, and leave eligibility `unknown` until the selected program's policy is checked. A named component without a CVE has no automatic vulnerability window.
2. **Choose a detectability map.** Web-visible components may surface in indexed headers/HTML/JS; language libraries in manifests/dependency graphs; native converters in package reverse-dependencies, Dockerfiles, vendor documentation, advisories, and already-indexed artifacts; server banners in public search indexes. Wappalyzer/Shodan product facets will commonly miss backend converters. Wrapper dependency is not execution in a production bounty surface.
3. **Collect public evidence.** Search vendor-owned source/docs, public manifests, GHSA/NVD and distro trackers, and already-indexed output. Record exact URL, observation date, product/owner identity, component, and one label: `source-derived`, `disclosure`, `artifact`, `feature-inferred`, `contradicted`, or `unknown`. `feature-inferred` (e.g., “PDF preview”) is only a hypothesis. For every query retain the map and query used; empty results mean only that those maps did not yield a hit. Do not fetch live generated documents from a candidate application as a confirmation shortcut.
4. **Join to a public directory.** Use [scripts/README.md](scripts/README.md) and `bbh skills/stack-to-program/scripts/stack_to_program.py` for repeatable evidence-to-program joins. Supply a dated local snapshot of ProjectDiscovery's public-bugbounty-programs `dist/data.json` and curated evidence JSONL. Exact name/explicit program URL or owner-domain equality are **candidate associations**, not proof of a production deployment. Reject third-party fork/repo-name and substring joins. Keep unmatched products, contradictions, and stale evidence visible.
5. **Verify paid and scope separately.** Pass promising candidate rows to `program-finder` for a current first-party bounty/rules page, paid status, exclusions, activity/payout evidence, and fit. The community directory `bounty: true` flag is not current payment proof. Ask Ryushe to choose a program. Only then follow the normal scope and live-testing gates; never label a program or host “vulnerable” from this join.

## Output packet

- Component/CVE, advisory URL, affected/fixed ranges, publication and calculated gate date (or `unknown`); distinguish advisories from production versions.
- Detectability class; maps/queries/date and coverage limits.
- Product and candidate program rows with evidence label, source URL, program page, join basis, and paid status `unverified` until `program-finder` confirms it.
- Contradicted/unmatched/feature-inferred rows separately; unknown production version, reachability, scope, and grace-period rule.
- Recommended first program to *inspect*, not to test; next handoff.

## Scale and confidence boundary

Batch public evidence records and directory snapshots, dedupe deterministically by component/product/source, and preserve provenance. Source-derived evidence establishes a dependency in the named source revision, not a deployed version. A CVE-to-product-to-directory chain narrows a queue, but every arrow has uncertainty. Public directories may be stale or incomplete, package reverse-depends include build/test/optional dependencies, and indexed artifacts may belong to third parties. Never auto-promote a candidate into a finding or a live scan queue. A selected program needs individually verified scope and rules before any host enumeration or target interaction.

Script map: [scripts/README.md](scripts/README.md) — deterministic offline public-evidence join; no target traffic.
