---
name: temporary-email
description: "Create and read disposable Mail.tm inboxes for owned test account setup."
---

# Temporary Email

Use when Codex or Claude needs a disposable inbox for an owned target account.

This skill only manages temporary inboxes and verification mail. It does not manage Ghost's Gmail and it does not create durable researcher accounts.

Temporary inboxes and target accounts must carry an explicit destructible status. Default is `destructible: no`.

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
2. Use temporary inboxes when Ryushe asks for a temporary account or when a workflow needs an account that may be burned.
3. If the target blocks or rejects the temporary email domain, stop and tell Ryushe the domain was blocked. Wait for Ryushe to provide an email address; do not try alternate disposable providers or bypass the block.
4. Read only owned temporary inboxes created for testing.
5. Store resulting target-account credentials in Bitwarden when an account is created.
6. Record only the account alias, email reference, target, purpose, destructible status, and Bitwarden item reference in notes.
7. Mark `destructible: yes` only when the inbox/account is explicitly intended for mutation, deletion, burn, or destructive-flow testing.
8. Program-domain emails default to `destructible: no` unless the stored email metadata clearly marks them destructible. A plus-addressed test identity such as `ryushe+ai3@program.com` may be marked destructible when that is its recorded purpose.
9. Do not paste mailbox passwords, target passwords, tokens, cookies, reset links, verification links, codes, or private message bodies into chat, prompts, findings, or reports.

## Account Note Format

When creating or recording an inbox/account, include:

```text
Account alias:
Email reference:
Target/program:
Purpose:
Destructible: yes|no
Destructible reason:
Credential store item:
Cleanup notes:
```

If destructible status is missing, treat the account as `destructible: no`.

## Stop Conditions

Stop and ask Ryushe if the target blocks the generated temporary email domain, requires phone/KYC, payment, SSO, a pre-approved account, explicitly bans disposable email, or the requested test needs a destructible account but none is marked `destructible: yes`.
