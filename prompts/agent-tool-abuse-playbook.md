# Agent Tool Abuse Playbook

Use when an AI feature can call tools, APIs, browser actions, workflow steps, or state-changing functions. The core question: can model-readable untrusted content or prompt pressure cause an action outside the real user's intent or authorization?

## 1. Tool Inventory

For each tool/action, record:

- name or inferred purpose
- read or write
- data class touched
- account/role used by the tool
- confirmation required
- whether the model writes tool arguments
- whether backend authorization validates the final target
- logs or UI traces available

Examples:

- edit document text
- add/delete page
- generate image prompt
- insert link
- export/share/publish
- invite collaborator
- send email/message/ticket
- browse/fetch URL
- scan/crawl URL
- construct HTTP request, Host header, redirect, or callback URL
- call debug/admin API
- call SQL/search/filter API
- render/export generated HTML, Markdown, JSON, or files
- search private data
- approve/reject/moderate
- buy/refund/update billing

## 2. Establish Baseline Intent

Write the user intent as a sentence:

```text
The user asked the AI to <legitimate task>. No user request authorized <sensitive action>.
```

Without this, the finding becomes vague.

## 3. Safe Tool Probes

Prefer:

- preview/draft mode
- no-op/sandbox/test resource
- scratch document or disposable test record
- dummy layer/text/title mutation
- operator-owned callback URL for outbound request observation

Callback rule:

```text
Use https://webhook.site/<owned-id>?case=<case-id> only as a canary.
Never encode secrets, cookies, PII, or private document values into the URL.
```

For scanner/fetch tools, a model saying it will fetch a URL is not enough. Prefer callback hits, request logs, scanner traces, or visible report output that proves the tool acted.

For AI-invoked SSRF-style probes:

- use owned callback URLs first
- use a unique case ID per attempt
- capture source IP, user agent, requested path/query, and timestamp
- record redirect behavior if redirects are part of the hypothesis
- do not ask the scanner to crawl broad internal ranges or unknown third-party systems

## 4. Argument Injection Checks

Inspect whether model output becomes:

- tool name
- resource ID
- URL
- email/message body
- document diff
- image prompt
- JSON/function arguments
- search query/filter
- publish/share setting
- Host/header/path/method fields
- redirect target
- scanner start URL or crawl scope

Look for missing confirmation, missing schema validation, or backend trust in model-generated arguments.

## 5. Stop Conditions

Stop and ask Ryushe before:

- sending messages or invites
- publishing/sharing externally
- making purchases/refunds/billing changes
- deleting content
- changing real customer/vendor data
- accessing private data beyond minimal classification
- triggering broad SSRF-like or crawler behavior

## Evidence Template

```md
# Agent Tool Abuse Finding

## Baseline Intent
- User requested:
- Tool/action not authorized:

## Tool Boundary
- Tool:
- Read/write:
- Acting role:
- Confirmation gate:
- Argument source:

## Reproduction
1. Controlled content/prompt:
2. Trigger:
3. Observed action or blocked action:
4. Cleanup:

## Evidence
- Full URL:
- Request/log IDs:
- Model output:
- Tool arguments:
- Callback evidence:
- Callback timestamp/source/UA:
- Redirect chain:
- Scanner request trace:
- Tool invocation trace:

## Impact
- Data/action affected:
- Same-user/cross-user/cross-tenant:
- Severity rationale:
```
