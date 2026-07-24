---
name: docs
description: Use when a bug bounty agent needs to retrieve, create, or update concise program-specific documentation linked to MapStore, such as SDK integrations, provider models, authorization objects, callback flows, or architecture.
---

# Program Docs

Program docs preserve costly, target-specific reconstruction without making
MapStore a verbose ledger. They are a linked expansion layer: MapStore stores
compact, queryable target facts; `docs/` stores the scoped model that explains
them.

Do not confuse this with ResearchMap. ResearchMap is curated, portable knowledge
promoted from reviewed external learning. Program docs are target-specific work
created during a program hunt.

## Retrieval Rule

Do not read a program's docs directory broadly at startup.

1. Start with the current task and concrete surface.
2. Load MapStore instructions, but do not ingest MapStore data broadly.
3. Query MapStore only with a concrete URL, integration, technology, or surface
   and an explicit intent.
4. If the MapStore result points to `docs/<topic>.md`, load that one document.
5. If a concrete technology or SDK is known but no MapStore pointer is available,
   use `program_docs.py search` with narrow terms.
6. Treat retrieved docs as a scoped working model, not proof. Validate material
   claims against current target evidence.

## Write Rule

Always record the concise, reusable target fact in MapStore. Add or update
program documentation when the fact needs an explanation future agents would
otherwise have to reconstruct: an SDK/provider integration, object or role
model, callback flow, architecture, or a multi-route behavior model.

Do not create a program doc for one response, raw tool output, copied vendor
documentation, or unlabelled speculation.

For direct MapStore writers:

1. Write the structured docs entry with `program_docs.py`.
2. Write the concise MapStore observation and include the printed `MapStore
   pointer: docs/<topic>.md` in its body.

For candidate-only/offline workers, propose the doc topic, body, sources, and
MapStore link in the candidate packet; the synthesis/promoter stage creates the
final linked MapStore and docs entries.

## Commands

Run from the Bug Bounty Harness root:

```bash
python3 agents/program_docs.py init --program <program> --family <family> --lane <lane>

python3 agents/program_docs.py search --program <program> --family <family> --lane <lane> \
  --query "poster sdk export"

python3 agents/program_docs.py show --program <program> --family <family> --lane <lane> \
  --topic integrations/poster-sdk-export-flow
```

Create a formatted document by supplying only the target-specific model and
provenance. The script supplies status, scope, recognition-signal prompts,
freshness caveats, and link sections:

```bash
python3 agents/program_docs.py write --program <program> --family <family> --lane <lane> \
  --topic integrations/poster-sdk-export-flow \
  --title "Poster SDK export integration" \
  --status partially-verified \
  --body-file /tmp/poster-sdk-model.md \
  --source "https://vendor.example/docs/sdk" \
  --source "working/scratch/<run-id>/sdk-notes.md" \
  --mapstore-ref "recon/maps/_app/poster-sdk/index.md" \
  --recognition "@imtbl/passport,relayerUrl/v1/transactions" \
  --question "Does the server bind submission to the Guardian-evaluated transaction?"
```

The command prints the canonical relative pointer, for example:

```text
MapStore pointer: docs/integrations/poster-sdk-export-flow.md
```

Use that pointer in the matching concise MapStore observation. Use `--overwrite`
only when intentionally replacing a document rather than extending it.

## Required Content

The supplied model must state only what is known for this program, with clear
uncertainty. Include, when available:

- confirmed SDK/package, endpoint, UI, header, or object recognition signals;
- object ownership and authorization boundaries;
- request, callback, webhook, export, or consumer flow;
- next discriminating security questions;
- program documentation URLs or sanitized artifact paths; and
- a MapStore reference once one exists.

Never put raw cookies, CSRF tokens, bearer/API/SDK tokens, or full proxy dumps
in program docs.

## Completion Check

Before finishing, verify all of the following:

- The document is at the program lane's `docs/<topic>.md` path.
- Its status and sources reflect what is actually verified.
- The linked MapStore observation remains concise and points to the doc.
- The document points to its MapStore record when known.
- Future agents can retrieve it by a concrete technology or surface term without
  ingesting the entire docs corpus.
