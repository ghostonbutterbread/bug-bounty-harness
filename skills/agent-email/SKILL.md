---
name: agent-email
description: "Create and read disposable Mail.tm inboxes with the agent-email CLI for approved testing workflows."
---

# Agent Email

Use when a bug bounty workflow needs a disposable inbox for approved signup, verification, invite, password-reset, account setup, or two-owned-account testing.

## Install

If `agent-email` is missing, install it with npm:

```bash
npm install -g @zaddy6/agentemail
```

Do not use the `npx skills add ...` install path for this workflow.

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

Manage stored inboxes:

```bash
agent-email accounts list
agent-email use <email|alias>
agent-email accounts add <email> --password <password> --set-default
agent-email accounts remove <email|alias>
agent-email config path
```

Aliases:
- `default`
- `active`
- `me`

## Workflow

1. Confirm disposable email is allowed for the target workflow and scope.
2. Prefer one inbox per target account or role. Record the account alias, not raw credentials, in hunt notes.
3. Use JSON output by default so agents can parse verification links and message IDs.
4. For isolated runs, set `AGENT_EMAIL_CONFIG` to a target-specific config path.
5. Read only messages for owned test inboxes.
6. Do not paste mailbox passwords, tokens, cookies, reset links, or private message bodies into chat, prompts, findings, or public reports.

## Storage

Default config path:

```text
~/.config/agent-email/config.json
```

The CLI stores mailbox credentials locally and enforces `0600` permissions on Unix. Treat this file as sensitive.

## Notes

- The CLI uses the Mail.tm API at `https://api.mail.tm`.
- Disposable domains may be blocked by some targets. If signup rejects the generated address, stop and use an approved account setup path instead of bypassing target policy.
- Use this skill to support account setup and email verification; vulnerability testing still belongs in the relevant child skill such as `/access-control`, `/idor`, `/csrf`, `/xss`, or `/pfp`.
