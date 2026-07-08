# AI Action Chain Playbook

Use this playbook when the bug bounty question is not just "can the model be jailbroken?" but "can attacker-controlled context make the AI cross a real app boundary?"

The loop is evidence-driven. Every pass should map, notice signals, keep a short hypothesis queue, choose the smallest next proof, verify with observable evidence, classify the result, and adapt.

## 0. Pentester Mode

Do not run this playbook as a checklist. Use it to preserve momentum once the target shows a signal.

Core loop:

```text
observe signal
  -> add/refresh hypothesis queue
  -> pick smallest next proof
  -> run bounded probe
  -> check evidence
  -> promote, pivot, chain, or kill
```

Signals worth branching on:

- reflected input, stored input, or model re-emission
- SQL/parser/template/path/header/CORS/auth errors
- 401/403/404/500 differences across auth state, method, host, headers, or content type
- internal hosts, admin paths, callback hits, redirects, request traces, scanner tool calls
- generated JSON/Markdown/HTML/URL/function args containing attacker-controlled content
- object IDs, org/workspace/design IDs, hidden fields, invite/share/export endpoints
- visible model/scanner summaries that disagree with backend state

Hypothesis queue format:

```text
Signal:
Hypothesis:
Boundary:
Smallest next proof:
Evidence required:
Pivot/kill condition:
Narrow skill handoff:
```

Rules:

- Keep 2-4 live hypotheses, not one obsession.
- Prefer one discriminating probe over more wording variants.
- If a probe yields only a report, summary, or assistant claim, pivot to evidence: request shape, tool args, backend logs, callbacks, or state delta.
- If evidence contradicts the model/scanner narrative, trust the evidence.
- Kill stale hypotheses explicitly so the next agent does not repeat them.

## 1. Action Surface Map

Start with a compact map. If one already exists from `/ai-trust-map`, reuse and extend it.

Record:

- full URL, feature name, and intended AI task
- attacker-controlled inputs: prompt, document, comment, title, metadata, OCR, webpage, RAG chunk, email, ticket, tool output
- victim/private inputs: org data, design/project state, account data, support history, admin logs, scanner-visible pages
- model execution identity: user browser, backend assistant, support/admin tool, authenticated scanner, background job
- capabilities: read, search, fetch, scan, edit, export, share, invite, message, classify, approve, call APIs, write memory
- output sinks: UI text, Markdown, HTML, JSON, tool/function args, generated files, exports, reports, cached summaries, logs
- evidence sources: proxy, backend AI logs, callback server, UI state, lab solved state, audit logs, diffable test objects

## 2. Pick One Boundary

Choose one boundary per loop. Good boundary labels:

- `model-mediated-idor`: AI can read, summarize, search, or act on an object the user cannot access directly.
- `tool-argument-smuggling`: untrusted content controls `url`, `user_id`, `org_id`, `design_id`, `query`, `filter`, `body`, `callback`, `host`, or similar fields.
- `fake-tool-state`: untrusted content claims a function already ran, approval already happened, or a previous step returned a value.
- `indirect-action`: stored attacker content changes another user's AI action later.
- `output-sink`: AI output is trusted as HTML, Markdown, JSON, URL, diff, or function args.
- `scanner-ssrf`: AI scanner/crawler/fetcher makes attacker-steered requests from a privileged network or auth context.
- `persistence`: injected instruction survives in memory, saved object state, cached summary, or reusable workflow context.

Boundary hypothesis shape:

```text
If <attacker-controlled input> is read during <AI task>, the model may influence <action/tool/output> against <object/context> that <user role> cannot normally control.
```

## 3. Probe Families

Pick 2-4 families. Record why each family targets the observed boundary.

### Fake Tool Output / Fake State

Use when the model reads logs, tickets, prior steps, RAG chunks, page text, or scanner content.

Signals:

- model treats untrusted text as a completed tool result
- model skips confirmation because text claims approval
- model continues to the next action using attacker-supplied state

Safe first target: fake status, fake request ID, fake canary, owned test object.

### Argument Smuggling

Use when model output becomes tool args, API params, filters, URLs, headers, paths, or request bodies.

Signals:

- generated arguments contain attacker-chosen object IDs, org IDs, URLs, callbacks, filters, or headers
- backend accepts model-generated args without revalidating authorization
- model copies untrusted text into structured output or tool calls

Safe first target: owned object IDs, harmless filters, callback URL with unique case ID.

### Schema / Format Pressure

Use when downstream systems expect JSON, YAML, Markdown, HTML, CSV, function calls, diffs, image prompts, URLs, or report fields.

Signals:

- protected values are echoed in `blocked_values`, `reason`, `evidence`, `tool_args`, or `safe_reason`
- untrusted content lands in structured fields that later drive actions
- renderer or parser treats model output as trusted markup or instructions

Safe first target: fake canary, placeholder values, inert HTML/Markdown markers.

### Indirect Stored Content

Use when another user, admin, support agent, reviewer, or scanner later reads attacker-controlled content through AI.

Signals:

- victim model mentions attacker canary
- victim model changes decision/action/tool args because of stored content
- stored content persists across sessions or workflow steps

Safe first target: owned comment/doc/template/profile field and benign action canary.

### Context Boundary / Delimiter Confusion

Use when app prompts concatenate trusted instructions, tool output, user content, and retrieved content.

Signals:

- data delimiters are treated as instruction boundaries
- injected "system", "developer", "tool", or "audit log" text changes behavior
- model follows instructions from quoted, code-fenced, or log-like content

Safe first target: ask for source classification or a non-sensitive marker.

### Encoding / Representation Mutation

Use when filters catch obvious English instructions or when content passes through OCR, rich text, filenames, markdown, JSON escaping, Unicode, or multilingual transforms.

Signals:

- encoded/confusable/translated instructions affect behavior differently from plain text
- model decodes/transforms untrusted content into tool args or output sinks

Safe first target: fake canary and benign action intent. Record the transformation family instead of accumulating raw payload strings.

### Long-Context / Salience Pressure

Use when the AI reads large docs, pages, exports, scanner results, or multi-turn threads.

Signals:

- later untrusted text overrides earlier task constraints
- repeated or strategically placed text changes summarization, action selection, or output fields

Safe first target: repeated benign canary and a harmless output preference.

### Scanner / Fetch Network Indirection

Use when the AI can fetch, scan, crawl, preview URLs, follow redirects, construct requests, or produce scanner start URLs.

Signals:

- callback hit
- controlled redirect followed
- Host/header/path/method changes in request logs
- scanner report includes attacker-steered URL or internal route behavior

Safe first target: operator-owned callback URL with case ID. Never put secrets, cookies, PII, or private document values in callback paths or query strings.

### Scanner SSRF Follow-Through

Use when a scanner identifies SSRF or internal routing but does not complete the impact.

Signals:

- scanner report says SSRF exists but lab/app state does not change
- tool calls show only public paths, or omit Host/header/absolute URL details
- scanner retrieves an admin page but does not follow the state-changing link
- scanner mistakes a stock count, generic 200, or report text for impact

Next probes:

- map exact request-construction authority: method, absolute URL, path, Host header, body field, redirect following, cookies, and auth context
- test discovery and action as separate hypotheses: first prove admin page fetch, then prove delete/action follow-through
- prefer callback or proxy-visible request traces when available
- use object IDs or exact internal URLs only when they are already observed in the lab/app evidence
- if scanner summarizes success without state change, classify `report-only-scanner-failure` and change route instead of rewording

Pivot routes:

- `/ssrf` when the controllable field is a URL or redirect target
- `/headers` when Host, forwarded headers, or route selection matter
- `/request-exploration` when method/body/content-type/schema shape controls the sink
- `/agent-tool-abuse` when the scanner tool schema or arguments are directly steerable

## 4. Evidence Gates

Rank evidence:

- weak: model says it would act
- moderate: model output contains changed decision, tool args, or rendered canary
- strong: proxy request, callback hit, backend AI/tool log, lab solved state, UI/state delta, saved draft diff, scanner trace

Do not promote a claim unless evidence matches the boundary.

Examples:

- SSRF-like scanner finding needs callback/request trace, not a model claim.
- Tool-abuse finding needs a tool call, generated actionable arguments, or state delta.
- IDOR finding needs object IDs and authorization context, not only a hallucinated summary.
- Output-sink finding needs rendered behavior or downstream parser consumption.
- If visible assistant text conflicts with backend/tool/log/lab evidence, prefer the backend evidence. The assistant may report failure after a tool/action already caused side effects.
- When object names contain quotes, formatting, leetspeak, non-ASCII punctuation, or ambiguous names, prefer stable product/object IDs for tool calls and record name-vs-ID behavior.

## 4.1 Output-Sink Ladder

For AI output rendered as chat, HTML, Markdown, JSON, report fields, or function args, escalate in this order:

1. direct chat inert marker
2. direct chat inert markup or harmless XSS canary in an owned lab
3. stored content encoding check in the original sink
4. model re-emission check through tool/RAG/product lookup
5. approved lab objective or explicitly approved state-changing action

This distinction matters: the original stored content may be safely encoded, while model-reemitted content may become unsafe in a different sink.

## 5. Block Classification

After each attempt, classify the result before mutating:

- `no-signal`: no model or tool behavior changed
- `model-refusal`: model refused before output/action
- `schema-block`: output/tool schema rejected fields
- `confirmation-gate`: app requested human confirmation
- `permission-block`: backend authorization denied the action
- `validation-block`: URL/ID/filter/content validation stopped it
- `hallucinated-action`: model claimed success but no evidence exists
- `report-only-scanner-failure`: scanner reports or describes exploitability, but request/state evidence does not prove impact
- `output-only-signal`: model output changed, but no action occurred
- `tool-arg-signal`: model produced attacker-influenced tool args
- `tool-action-signal`: action/tool/request occurred
- `cross-boundary-impact`: unauthorized object/action/data/output boundary was crossed

Mutation rule:

- Refusal -> change family, not just wording.
- Schema block -> test another sink or valid inert field.
- Permission block -> record as defense; do not brute force.
- Confirmation gate -> test whether injected content can alter confirmation text, not bypass it.
- Hallucinated action -> require logs/proxy/callback before continuing.
- Report-only scanner failure -> stop rewording the prompt; map request construction or pivot to SSRF/headers/request exploration.
- Tool-arg signal -> hand off to `/agent-tool-abuse`, `/idor`, `/access-control`, `/request-exploration`, `/ssrf`, or `/headers` based on the field.

## 6. PortSwigger Validation Mode

Use hard Web Security Academy Web LLM labs as controlled validation targets. They are authorized labs; destructive actions are allowed only when they are the explicit lab objective.

Preferred hard-lab order:

1. indirect prompt injection
2. insecure output handling in LLMs
3. AI scanner sensitive-information exfiltration
4. bypassing AI scanner defenses
5. AI scanner secondary vulnerability / routing-based SSRF

Per lab, write:

```text
trust-map.md
action-boundary.md
probe-plan.md
run-log.md
evidence.md
skill-gap-notes.md
```

Grade the skill on:

- mapping completeness before solve
- whether it selected the right boundary
- whether it chose probe families for the observed defenses
- whether it required backend/tool/callback/lab evidence
- what it guessed wrong

## 7. Flourish-Style Model-Mediated IDOR

For Flourish or similar design/org tools, hunt for a confused-deputy chain:

```text
attacker-controlled design/comment/template/metadata
  -> AI reads it during assist/review/export/search
  -> model fills object/action args
  -> backend/tool uses AI's authority or broader context
  -> private org/design/data source is read, summarized, edited, exported, shared, or referenced
```

Map candidate object classes:

- design/project/workspace/org IDs
- template IDs
- data source IDs
- embed/export/share URLs
- invite/collaboration targets
- comments/notes/review fields
- brand assets or media libraries
- analytics/report objects

Safe first probes:

- owned design to owned design
- owned org object with a fake canary
- read-only summarization or preview
- draft-only edit
- callback-only fetch
- cross-account object only after Ryushe confirms ownership and scope

## Output Template

```md
# AI Action Chain Run

## Target
- Program/lab:
- Feature URL:
- Goal:
- Mode:
- Operator approval:

## Trust Map Summary
- Attacker-controlled inputs:
- Private/victim context:
- Model identity:
- Tools/actions:
- Output sinks:
- Evidence sources:

## Boundary Hypothesis
- Boundary:
- Hypothesis:
- Stop conditions:
- Safe canary/callback:

## Probe Plan
- Signal:
- Hypothesis queue:
- Family:
- Why this family:
- Attempt:
- Expected evidence:
- Stop/mutation rule:

## Run Log
- Attempt:
- Input/control point:
- Observed output:
- Evidence:
- Classification:
- Cleanup:

## Result
- Best signal:
- Impact class:
- Confidence:
- Handoff:
- Next step:
- Killed hypotheses:
```
