---
name: data-store-guidance
description: "Use when starting bounty work or choosing a store."
---

# Data Store Guidance

This is the store-ownership map: what each store holds and its owning skill.
Commands, schemas and procedures belong to those owning skills.

- **Scope** — program rules and permitted assets. Owner: `/pullscope`.
- **Recon** — collected host, URL, parameter and asset inventories, aggregates and run manifests. Owners: `/recon`, `/recon-ry`.
- **URL/parameter review** — URL and parameter observations, imports and review state. Owner: `/url-ingest`.
- **Runtime maps** — observed application routes, flows, objects and auth boundaries. Owner: `/live-map`.
- **JavaScript** — retained bundles, source maps, provenance and analysis packets. Owners: `/js`, `/js-pull`, `/js-hunt`.
- **Endpoint/API/parameter outputs** — endpoint contracts, API graphs and parameter inventories. Owners: `/analyze-endpoint`, `/api-surface-mapping`, `/parameter-mining`.
- **MapStore** — reusable application facts, observations and named Application Behaviors. Owner: `/map-store`.
- **Static AppMap** — source-code application maps and research campaigns. Owners: `/appmap`, `/appmap-research-librarian`.
- **Public Leads** — evidence-backed cross-run leads stored in MapStore. Owner: `/leads`.
- **Private hypotheses** — owner/run-private candidates and their lifecycle. Owner: `/hypothesis-ledger`.
- **Attempts** — exact deliberate target-directed test history. Owner: `attempt-recording-policy`; BBH adapter: `agents/attempts.py`.
- **Live Coverage** — mapped surface/input/consumer/class questions and scoped review assessments. Owner: `/coverage`.
- **Static Coverage** — file/class review against a Shared Brain source snapshot. Owner: `/coverage`.
- **Notes** — published coordination, timelines, handoffs and working-artifact pointers. Owner: `/bounty-notes`.
- **Program Docs** — program-specific application and technology models. Owner: `/docs`.
- **Portable ResearchMap** — reusable security research, source material and mechanism cards. Owner: `/research-knowledge-management`.
- **Findings** — finding identity, dedupe, lifecycle and evidence records. Owners: `/ledger`, `/findings`, `/manual-hunter`.
- **Reports** — FID-linked evidence packets and registered final-report paths. Owners: `/ledger` for packet references; `bunny-report-and-triage` for final authoring.
- **Blockers** — external prerequisites and reopen conditions. Owner: `/blockers`.
- **Errors** — error fingerprints and supporting evidence pointers. Owner: `/error-intelligence`.
- **Safety incidents** — safety-event and notification records. Owner: Core safety-incident store; BBH interface: `scripts/safety_incident.py`.
- **Owned accounts/resources/connections** — program-scoped non-secret ownership, account and integration metadata. Owners: `/account-registry`, `/account-management`.
- **Owned public test artifacts** — published fixtures, ownership, lifecycle and cleanup records. Owner: `/public-artifacts`.
- **Browser/proxy/auth state** — node-local profiles, leases, auth material and captures. Owners: `/chromium-test`, `/agent-proxy` and the applicable proxy policy.
- **Retained artifacts** — retained files and their manifests/location pointers; storage-tier guidance. Owners: producer manifests and `/bounty-storage`.

When a persistent store is added, renamed, retired or changes purpose, update
this map in the same change.
