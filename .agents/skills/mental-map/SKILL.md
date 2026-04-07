---
name: mental-map
description: Build mental maps of application architecture by analyzing Caido MCP proxy traffic, grouping requests into flows like auth, cart, checkout, signup, login, forgot-password, and user-profile, then documenting sequence diagrams and replication notes
---
# Mental Map Analysis

Build mental maps of application architecture from Caido MCP proxy traffic.

## Required Preflight

Read shared state in this order before mapping flows:

1. `notes/summary.md`
2. `notes/observations.md`
3. `checklist.md` (auth, workflow, and business-logic items only)
4. `todo.md` (workflow mapping or prerequisite items only)

## Primary Analysis Surface

There is no dedicated `agents/mental_map.py` harness in this repo. Use Caido MCP proxy traffic as the source of truth, set the browser or replay client proxy to `KAIDO_MCP_PROXY_URL`, then classify captured requests into application flows.

## What To Map

Prioritize end-to-end flows another agent would need to replay safely:

- `auth`
- `signup`
- `login`
- `forgot-password`
- `user-profile`
- `cart`
- `checkout`
- Any custom billing, admin, search, upload, or API workflow that materially changes state

## Files

- **Playbook:** `$HARNESS_ROOT/prompts/mental-map-playbook.md`
- **Output Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/application-structure/`
- **Flow Template:** `$HARNESS_ROOT/agent_shared/templates/application-structure/flow-template.md`

## Output Contract

Write one markdown file per flow to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/application-structure/{flow-type}/{flow-name}.md`

Each flow file must include:

- Domain
- Endpoints involved
- Request sequence
- Auth requirements
- Session handling and CSRF notes
- Data model
- State transitions
- Replication notes for another agent

## Workflow

1. Complete the required preflight reads in shared state order.
2. Read `prompts/mental-map-playbook.md`.
3. Connect the browser or replay client to `KAIDO_MCP_PROXY_URL` and capture the real workflow.
4. Group requests into a concrete flow with entry points, dependencies, and state-changing operations.
5. Write the diagram and structured notes to `agent_shared/application-structure/{flow-type}/{flow-name}.md`.
6. Update `notes/summary.md`, `notes/observations.md`, and `todo.md` when the map exposes new testing lanes or prerequisites.
