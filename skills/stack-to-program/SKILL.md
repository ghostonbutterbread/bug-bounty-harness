---
name: stack-to-program
description: "Use when mapping a CVE or technology to bounty programs through public evidence."
---

# Stack-to-program

- **Use when:** the starting point is a CVE, component, library, native converter, or product stack—not a selected program.
- **Purpose:** discover broad, evidence-labeled product and program *leads* from public information, then narrow by policy and program-specific documentation. This is selection research, not live target enumeration or a vulnerability claim.
- **Method:** choose a visibility branch, expand the component-to-feature graph where necessary, join owners to program directories, verify current rules, then hand off selected targets to the normal testing lanes. Read [the visibility and bridge guide](references/visibility-and-bridges.md) for the generic decision model. If Ghostscript, Artifex, `gs`, or a Ghostscript CVE is named, also read [the Ghostscript augment](references/ghostscript.md).

## Discovery flow

1. **Define the component and advisory, if any.** Resolve aliases, upstream versus distro packages, affected and fixed ranges, release/advisory dates, and the behavior or configuration needed for the issue. A named stack need not imply a CVE. Do not equate an upstream version string with a distro's backported patch status. An operator's “30 days” is not universal eligibility: leave each program's disclosure or patch-window rule unknown until checking its published policy.
2. **Choose the visibility branch.** For a directly observable technology, search public indexes and already published artifacts for that product/version; skip private-dependency inference unless the specific issue needs an unseen backend edge. For a private library or converter, work *outward* through documented callers, optional delegates, package dependencies, formats, and feature archetypes to find products that might invoke it. Mixed stacks can use both branches. Follow the evidence ladder and negative paths in the [generic guide](references/visibility-and-bridges.md); do not treat installation or generic image/PDF support as execution.
3. **Enumerate public maps broadly.** Search vendor-owned repositories and manifests, installation/deployment docs, SBOMs, advisories, integration and API docs, public indexed artifacts, and program-facing documentation where already published. Preserve the query/map, source URL, product/owner attribution, observation date, and limits for each pass. Search alternate names and competing implementations; a zero-hit query is not evidence of absence. Public technology-index hits may point to a hostname but are not themselves an invitation to query it. No candidate application requests, host scans, file uploads, accounts, or direct API probes occur in this discovery lane.
4. **Produce candidate product/program associations.** Curate evidence JSONL and use [the offline join CLI](scripts/README.md) with a dated local ProjectDiscovery directory snapshot. Exact explicit program URL, exact owner domain, or exact normalized product/program name are candidate joins, not ownership proof or scope. No fuzzy substrings, third-party repo attribution, or automatic promotion from a directory's `bounty` flag. Keep unmatched, contradiction-only, and feature-only hypotheses visible; do not force a lead into a match. The CLI scales the *join*, not collection or host enumeration.
5. **Enrich the shortlist from public program and product material.** `program-finder` verifies current paid status, canonical rules, exclusions, and eligible assets; published product/API/help docs indicate whether an in-scope feature plausibly reaches the vulnerable behavior and what competing paths exist. This enrichment can prioritize more surfaces within a promising program, but neither documentation nor a published scope wildcard proves that any host runs an affected version. Record uncertainty and provenance rather than a binary vulnerability verdict.
6. **Select and hand off.** Recommend program(s) and specific feature questions with their evidence, unknowns, and public policy links. Once a program is selected, initialize it through the normal `general-security-testing-policy`, `program-testing-policy`, `/pullscope`, and applicable recon/technology-research lanes **before** live candidate interaction. Target-side feature mapping, version verification, and vulnerability validation belong there, under that program's current rules—not in this skill. Selection may be operator-directed; a public shortlist alone does not grant testing permission.

## Evidence packet

- Component/CVE, aliases, authoritative advisory and affected/fixed ranges (or unknown), relevant dates and program-specific time-rule status.
- Visibility choice and coverage: exact public maps/queries/date, source ownership, negative/alternate evidence, and limits; separate product release/version evidence from deployment evidence.
- Product → feature → component edges with label and source per edge; distinguish a direct implementation from an optional wrapper, a feature archetype, and a mere indexed banner. Note competing implementations and path-specific contradictions.
- Candidate company/program, directory snapshot ID, join basis, current paid/rules verification if available, potential in-scope feature, and explicit unknowns (deployment, executable path, version, authorization).
- First program to inspect, not an automatically testable host list; selected-program handoff question and next skill.

## Augment contract

The main flow owns public discovery, uncertainty, joining, and the scope boundary. A technology-specific `references/<component>.md` augments it only when a distinct interpreter, wrapper, format, dependency, or detection pattern changes the search. Keep that reference narrow: aliases and advisory caveats; direct and optional caller edges; high-signal public queries/owned sources; competing paths; feature/format signals; a non-claim example and handoff questions. Source the edges and label observed versus inferred; do not duplicate the directory CLI, program eligibility, or live-testing procedure. The [Ghostscript augment](references/ghostscript.md) is the first example. Add more only when there is concrete evidence for that technology.

**Related skills**

- Without a stack criterion, or when verifying a paid shortlist, load `program-finder`.
- Once a program is selected for target interaction, load `general-security-testing-policy`, `program-testing-policy`, `/pullscope`, and the relevant recon/technology-research specialist.

Script map: [scripts/README.md](scripts/README.md) — deterministic offline public-evidence join; no target traffic.
