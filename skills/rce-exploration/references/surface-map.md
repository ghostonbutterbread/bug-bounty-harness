# RCE Surface Map

Classify the full path before selecting a test. A useful hypothesis reads:

`attacker-controlled input → transform/validator → interpreter boundary → execution context → observable effect`

## High-yield sink families

| Family | Look for | Prove before escalation |
|---|---|---|
| Command construction | diagnostics, converters, archive/image/media helpers, package/build hooks, network utilities | Whether an OS process is invoked and whether input reaches a shell, argument, filename, option, or environment value |
| Template rendering | previews, email/PDF/report generation, CMS themes, error pages, user-configurable messages | Whether input is data or template source; identify the actual rendering engine |
| Deserialization | signed/session blobs, queues, caches, RPC, imports, binary/object formats | Format, trust boundary, library/runtime, and a safe object-processing signal |
| Upload and conversion | file upload, import, preview, OCR, media/document conversion, extraction | Storage location, downstream parser/converter, fetch behavior, and whether any later consumer interprets the file |
| Parser-to-executor chain | XML, archives, document formats, config/import DSLs, URL fetchers | Parser feature, transformed artifact, and any hand-off to a command/template/job executor |
| Job, automation, and deployment | CI/CD, scheduled reports, webhooks, repository integrations, build settings | Trigger authority, attacker-controlled field, worker context, and an owned job-only signal |

## Transform questions

For every candidate field, identify: decoding order; canonicalization; quoting/escaping; allowlist or blocklist; content-type handling; archive/container extraction; filename versus contents; storage versus retrieval path; sync versus async processing; cache; retries; and the account/worker privilege at the final consumer.

## Decision rule

Do not jump from input acceptance to RCE. Each mutation must distinguish one
edge in the path: reaches parser, changes parser behavior, reaches interpreter,
or produces a controlled execution signal. When the edge is unsupported, close
or remap the hypothesis rather than escalating payload complexity.
