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

## Program Scope Gate

`--program <program>` is a required retrieval and write filter, not a display
label. Before every `init`, `search`, `show`, or `write`, use the active
platform/program identifier from the current scope/run (for example,
`--program immutable`). Never search across programs, infer a program from a
provider name, or reuse a document solely because another platform uses the
same SDK. A cross-program pattern belongs in curated ResearchMap only after
review; target facts remain within that program's lane.

## Retrieval Rule

Do not read a program's docs directory broadly at startup.

1. Start with the current task and concrete surface.
2. Load MapStore instructions, but do not ingest MapStore data broadly.
3. Query MapStore only with a concrete URL, integration, technology, or surface
   and an explicit intent.
4. If the MapStore result points to `docs/<topic>.md`, load that one document.
5. If a concrete technology, SDK, or surface is known but no MapStore pointer is
   available, use `program_docs.py search` with narrow terms and/or structured
   filters (`--tag`, `--surface`, `--technology`). Do not search with generic
   vulnerability words alone.
6. Treat retrieved docs as a scoped working model, not proof. Validate material
   claims against current target evidence.

## Write Rule: Application Behavior

Use Program Docs for the compact model a future agent would otherwise need to
reconstruct about **this application's behavior**: how it uses an SDK/provider/
protocol, object or role model, callback, workflow, trust boundary, or
multi-route architecture. It may be a source-backed, `partially-verified` model
before a concrete target fact exists. State what is observed, source-derived,
and unknown; do not turn vendor documentation or an analogy into a target fact.

Route related knowledge deliberately:

- concrete observed target behavior, tested state, or constraint → MapStore;
- reusable, source-cited technology mechanism with a recognition signal and
  discriminator → ResearchMap;
- a selected, target-grounded test idea → Hypothesis Ledger;
- exact executed test history → Attempts.

When both a concise target fact and a longer application-behavior model exist,
link them: write the formatted doc with `program_docs.py`, then add its printed
`MapStore pointer: docs/<topic>.md` to the concise MapStore observation. Do not
manufacture a MapStore fact solely to justify useful program documentation.

Do not create a program doc for one response, raw tool output, copied vendor
documentation, or unlabelled speculation. A source-backed provider/SDK workflow
is useful only when it explains the active program, names recognition signals or
open questions, and would save future reconstruction.

When a Program Doc identifies a technology signal, an agent may query
ResearchMap for a matching portable mechanism. Treat the combined result as a
lead to validate against current target evidence—not proof or an automatic
hypothesis.

For candidate-only/offline workers, propose the doc topic, body, sources, and
any known MapStore link in the candidate packet; the synthesis/promoter stage
creates the final durable entry.

## Commands

Run from the Bug Bounty Harness root:

```bash
python3 agents/program_docs.py init --program <program> --family <family> --lane <lane>

python3 agents/program_docs.py search --program <program> --family <family> --lane <lane> \
  --query "poster sdk export"

# Metadata-only discovery when an agent knows the surface or technology but not the topic.
python3 agents/program_docs.py search --program <program> --family <family> --lane <lane> \
  --tag sdk --surface auth --technology poster-sdk

python3 agents/program_docs.py show --program <program> --family <family> --lane <lane> \
  --topic integrations/poster-sdk-export-flow
```

Create a formatted document by supplying only the target-specific model,
provenance, and small controlled discovery metadata. `--tag` is required;
use stable lowercase identifiers, while aliases capture expected alternate names
the next agent may use:

```bash
python3 agents/program_docs.py write --program <program> --family <family> --lane <lane> \
  --topic integrations/poster-sdk-export-flow \
  --title "Poster SDK export integration" \
  --status partially-verified \
  --body-file /tmp/poster-sdk-model.md \
  --tag "sdk,integration,export" \
  --alias "poster-client,workspace-export" \
  --surface "api,auth" \
  --technology "poster-sdk" \
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
