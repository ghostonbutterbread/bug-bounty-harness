# Access Control Account Setup

Access-control testing needs approved owned accounts and resources.

## Before Testing

- Confirm the program allows authenticated testing.
- Use approved owned accounts only.
- Prefer at least two same-role accounts for horizontal IDOR/BOLA.
- Prefer one low-privileged and one approved higher-privileged baseline for vertical checks.
- Prefer two owned orgs/workspaces/projects for tenant isolation checks.
- Create reversible, low-impact resources for testing: drafts, test files, private projects, test orders where allowed, private profile/media objects.

## Stored Context

Look for account/session notes under:

```text
$HARNESS_SHARED_BASE/{program}/credentials/
```

Known shared convention:

```text
~/Shared/bounty_recon/{program}/credentials/
```

Never print, persist to findings, or paste raw cookies, passwords, bearer tokens, auth headers, or session values into chat.

## If Accounts Are Missing

Stop and ask Ryushe for account setup or approval to create accounts.

Capture what is needed:

- program
- target domain/app
- required account count
- role mix needed
- tenant/workspace/project count needed
- resource types needed
- whether email/phone/payment verification is required
- exact safe test resources to create

Future account-creation skill idea: a dedicated router that handles signup policy, aliases, inbox/verification, test-resource creation, credential storage, and cleanup notes.
