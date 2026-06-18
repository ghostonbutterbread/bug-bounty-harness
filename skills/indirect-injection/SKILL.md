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

1. `$HARNESS_ROOT/prompts/indirect-injection-playbook.md`
2. `$HARNESS_ROOT/prompts/prompt-injection-playbook.md`
3. `/ai-trust-map` output if available

## Rules

- Start with harmless canaries and reversible test content.
- For callback tests, use an operator-owned callback URL such as webhook.site.
- Never place secrets, cookies, private data, or real user identifiers in callback URLs.
- Stop before destructive edits, spam, purchases, account changes, broad external requests, or sensitive-data exposure unless Ryushe explicitly approves the exact action.

## Evidence

Record attacker-controlled content, storage location, victim role, trigger action, model output/action, callback evidence if used, cleanup, and the crossed trust boundary.
