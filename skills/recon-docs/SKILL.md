---
name: recon-docs
description: Use when full or focused recon needs product/developer docs as bounded source evidence and Program Docs candidates.
---
# Recon Documentation Collection

Use `/recon-docs` to collect **public, program-specific documentation signals**
that broaden the observable application surface: product workflows, API and SDK
references, integrations, webhooks, import/export paths, roles, permissions,
and developer use cases.

It complements `/docs`:

- `/recon-docs` collects and normalizes source-attributed documentation records
  for a recon run.
- `/docs` creates or retrieves a compact, reviewed Program Doc once a source
  explains a real application workflow or boundary.

Do not create a parallel documentation database. Documentation is intended
behavior/context, not proof of target-side authorization or enforcement.

## Inputs and output

An agent collects a bounded JSON/JSONL source list. Each row may contain:

```json
{"url":"https://docs.example/api","kind":"api","title":"API overview","signals":["workspace","token"],"use_cases":["create project"]}
```

`kind` may be `product`, `developer`, `api`, `sdk`, `integration`, `webhook`,
`permission`, or `workflow`.

Normalize it without network retrieval:

```bash
bbh agents/recon_docs.py <program> --target <scoped-origin-or-host> \
  --input <agent-collected-docs.jsonl> --json
```

The command writes a `recon-docs` run capsule with
`parsed/developer_docs.jsonl`. It preserves source provenance and labels rows
`collected-unverified`; it does not create findings, test endpoints, or promote
an unreviewed document into Program Docs.

## Full recon use

During `/recon --full`, this is one focused collection lane alongside Recon-Ry,
runtime/live collection, and JS inventory. Its return packet should name:

- canonical source URLs and source artifact path;
- endpoint, SDK, role, provider, integration, or workflow signals;
- likely feature vocabulary for runtime/JS collection; and
- a narrow candidate `/docs` topic only when the material explains the program.

Use the resulting source artifact to enrich `/focused-recon` target packets or
create a reviewed `/docs` Program Doc. Keep target facts in MapStore and
candidate security questions in the Hypothesis Ledger, tagged `recon` plus a
specific surface tag.
