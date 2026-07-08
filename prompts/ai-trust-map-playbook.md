# AI Trust Map Playbook

Build a compact map before prompt-injection probes. The goal is to identify which text is trusted, which text is attacker-controlled, what the model can see, and what the model can do.

## 1. Feature Identity

Record:

- full target URL or app location
- feature name and user-visible purpose
- roles involved: attacker, owner, collaborator, admin, support, reviewer, anonymous user
- normal user intent
- whether the AI runs interactively, in the background, or during import/export/review

## 2. Model-Visible Inputs

List categories, not sensitive values:

- direct prompt and conversation history
- document/body text
- comments, notes, reviews, tickets, emails, chat messages
- filenames, titles, metadata, alt text, profile fields, brand-kit fields
- uploaded PDFs, images, OCR text, slides, templates, attachments
- webpages, search results, RAG chunks, snippets, cached summaries
- prior memory, project state, workflow history

Mark each source as:

- trusted app instruction
- user instruction
- attacker-controlled content
- victim/private content
- generated model output being fed back in

## 3. Capabilities

For each capability, record read/write, role, and confirmation gate:

- read private data
- edit document/design/page/profile/ticket
- add/delete/reorder content
- generate images or media
- export/download/share/publish
- invite or message users
- call internal APIs/functions/tools
- browse or fetch URLs
- scan or crawl URLs as an AI-powered scanner
- construct HTTP requests, headers, redirects, or callback URLs
- write memory or saved project state
- rank, moderate, approve, reject, recommend, or classify

For scanner or crawler agents, also record:

- scanner identity and account/role used
- crawl scope and depth if visible
- whether the scanner follows redirects
- whether the scanner can alter Host, headers, paths, methods, or request bodies
- network position: public browser, backend service, authenticated scanner, or internal network
- whether untrusted page content becomes model-visible instructions during the scan

## 4. Output Sinks

Check where model output lands:

- rendered document text
- comments or collaboration messages
- Markdown, HTML, URLs, alt text, filenames
- JSON/tool arguments
- image prompts
- generated files/exports
- cached summaries or memory
- admin/support/reviewer dashboards

## 5. Boundary Hypotheses

Write hypotheses in this shape:

```text
If <attacker-controlled input> is read during <AI task>, it may influence <output/action/tool> affecting <victim role>.
```

Pick the next lane:

- `/indirect-injection` when untrusted content controls model behavior
- `/agent-tool-abuse` when model actions/tools can mutate state or call outbound systems
- `/model-redteam-taxonomy` when choosing mutation families or evaluator strategy
- `/prompt-injection --mode output` when the main issue is unsafe rendering or structured output

## 6. Safe Canary Plan

Prefer unique markers and operator-owned callback URLs:

- text marker: `GHOST_PI_CANARY_<timestamp>`
- callback marker: `https://webhook.site/<owned-id>?case=<case-id>`

Never include secrets, cookies, bearer tokens, private document text, PII, or customer data in callback URLs.

## Output Template

```md
# AI Trust Map

## Feature
- Program:
- URL:
- Feature:
- Intended task:
- Roles:

## Actor / Execution Context
- Human user:
- Model/agent:
- Tool/scanner identity:
- Account/role used:

## Inputs
- Trusted instructions:
- User prompts:
- Attacker-controlled sources:
- Private/victim sources:
- Generated feedback loops:

## Capabilities
- Read:
- Write:
- External/callback:
- Memory:
- Confirmation gates:

## Network Egress
- Fetch/scan capability:
- Redirect behavior:
- Header/Host control:
- Internal route exposure:
- Callback evidence available:

## Tool/API Inventory
- Tool/API:
- Arguments:
- Acting role:
- Authorization checked by:
- Logs/traces:

## Output Sinks
- Rendered:
- Structured:
- Tool args:
- Persistent:

## Next Lane
- Recommended skill:
- Boundary hypothesis:
- Canary:
- Stop conditions:
- Evidence needed:
```
