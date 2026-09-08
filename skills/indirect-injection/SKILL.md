---
name: indirect-injection
description: "Test attacker-controlled content that an AI feature reads through docs, pages, comments, files, OCR, RAG, or shared artifacts."
---
# Indirect Injection

Use when untrusted content may influence another user, role, workflow, AI summary, AI decision, tool call, memory, generated artifact, or output sink.

## Invocation

```text
/indirect-injection <program> <target_url-or-surface> [--artifact <path>] [--callback <url>] [--dry-run]
```

## Load Order

Before live work, read [AI action boundaries](../ai-tester/references/action-boundaries.md)
and load the shared security-policy owners it names. Owning the stored content
does not establish ownership of its readers or downstream effects.

1. `prompts/indirect-injection-playbook.md`
2. `prompts/prompt-injection-playbook.md`
3. `/ai-trust-map` output if available

## Rules

- Start with harmless canaries and reversible test content.
- For callback tests, use an operator-owned observer only when the request and observer are authorized under the linked action boundaries.
- Never place secrets, cookies, private data, or real user identifiers in callback URLs.
- Apply the linked live/account/class approval and stop gates to the actual effect, including every later consumer. Disposable application fixtures are distinct from protected server state; unexpected unapproved effects require a stop and evidence preservation.

## Evidence

Record attacker-controlled content, storage location, victim role, trigger action, model output/action, callback evidence if used, cleanup, and the crossed trust boundary.
