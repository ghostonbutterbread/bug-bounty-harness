---
name: temporary-email
description: "Create and read disposable Mail.tm inboxes for approved agent account setup."
---

# Temporary Email

Use when Codex or Claude needs a disposable inbox for an approved target account.

This skill only manages temporary inboxes and verification mail. It does not manage Ghost's Gmail and it does not create durable researcher accounts.

## Commands

Create a mailbox:

```bash
agent-email create
```

Read latest messages:

```bash
agent-email read <email|alias> --limit 10
agent-email read <email|alias> --wait 60 --interval 3
```

Show one message:

```bash
agent-email show <email|alias> <messageId>
```

List known temporary inboxes:

```bash
agent-email accounts list
agent-email config path
```

## Rules

1. Confirm disposable email is not explicitly prohibited for the target workflow.
2. Use temporary inboxes when Ryushe asks for a temporary account or when testing permanent account deletion/burn flows.
3. Read only owned temporary inboxes created for testing.
4. Store resulting target-account credentials in Bitwarden when an account is created.
5. Record only the account alias, email reference, target, purpose, and Bitwarden item reference in notes.
6. Do not paste mailbox passwords, target passwords, tokens, cookies, reset links, verification links, codes, or private message bodies into chat, prompts, findings, or reports.

## Stop Conditions

Stop and ask Ryushe if the target requires phone/KYC, payment, SSO, a pre-approved account, or explicitly bans disposable email.
