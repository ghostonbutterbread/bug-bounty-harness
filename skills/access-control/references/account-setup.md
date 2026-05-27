# Access Control Account Setup

Access-control testing needs owned accounts/resources with clear role, tenant, and destructible status.

## Before Testing

- Confirm the program allows authenticated testing.
- Use owned accounts only.
- Prefer at least two same-role accounts for horizontal IDOR/BOLA.
- Prefer one low-privileged and one owned higher-privileged baseline for vertical checks.
- Prefer two owned orgs/workspaces/projects for tenant isolation checks.
- Create reversible, low-impact resources for testing: drafts, test files, private projects, test orders where allowed, private profile/media objects.
- Treat all accounts as `destructible: no` unless the stored account note explicitly marks `destructible: yes`.
- Use destructive flows only with accounts/resources marked `destructible: yes`.

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

Use existing owned accounts when available. Load `/temporary-email` only when a disposable inbox is needed or the test needs an account that may be deleted, burned, or destructively mutated. Do not improvise signup, credential handling, CAPTCHA handling, or password-manager writes inside `/access-control`.

If scope, ownership, policy, or destructible status is unclear, stop and ask Ryushe for account setup clarification.

Capture what is needed:

- program
- target domain/app
- required account count
- role mix needed
- tenant/workspace/project count needed
- resource types needed
- whether any account/resource must be destructible
- whether email/phone/payment verification is required
- exact safe test resources to create

Expected `/temporary-email` return data when a disposable account is created:

- account aliases, not raw credentials
- email reference
- destructible status: `yes` or `no`
- destructible reason, if `yes`
- role, tenant, workspace, org, project, and resource relationships
- inbox reference
- Bitwarden or credential-store item reference
- cleanup notes
- blockers and manual steps
