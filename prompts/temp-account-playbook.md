# Temp Account Playbook

Use this when an agent needs owned temporary accounts for scoped testing.

## Goal

Create the smallest safe account setup that lets the caller test the boundary without risking Ryushe's normal accounts or real users.

Prefer:
- one account per role or tenant boundary
- one disposable inbox per account
- private, reversible test resources
- aliases in notes instead of secrets

## Preflight

Confirm before signup:
- program and target domain are in scope
- account creation is allowed by the program rules
- disposable email is allowed or at least not prohibited
- required account count, role mix, and tenant/workspace/project count
- intended test actions and which ones are destructive
- whether phone, payment, SSO, or manual approval is required

Stop and ask Ryushe if the flow requires payment, phone verification, public posting, messaging real users, bulk creation, bypassing anti-abuse controls, or actions outside scope.

## Disposable Inbox

Use `/agent-email`.

Preferred commands:

```bash
agent-email create
agent-email read <email-or-alias> --wait 90 --interval 3 --limit 10
agent-email show <email-or-alias> <message-id>
```

Use JSON output when available so verification links and codes can be parsed. Read only owned inboxes created for this test.

Do not print mailbox passwords, verification links, reset links, codes, or private message bodies in chat, prompts, findings, or reports.

## Browser Signup

Use `/chromium-test` or another approved browser automation skill.

Default flow:

1. Launch an isolated browser profile for the program and task.
2. Navigate to the in-scope signup URL.
3. Fill only required signup fields.
4. Use the disposable inbox for verification links or codes.
5. If CAPTCHA appears, pause for manual completion or explicit approval. Do not bypass or outsource CAPTCHA solving.
6. Finish only non-sensitive onboarding steps needed for testing.
7. Create the minimum private owned resources requested by the caller.

Avoid normal Ryushe browser profiles. Avoid broad profile reuse unless the caller explicitly asks for the same account context.

## Credential Storage

Use Bitwarden when available.

Preferred rules:
- verify `bw` exists before relying on it
- unlock/authenticate without exposing tokens
- store the username/email, generated password, target URL, role, tenant, and notes
- record only the Bitwarden item ID/name and account alias in hunt notes
- never echo generated passwords or session material

If Bitwarden is unavailable or locked and cannot be used safely, stop and ask Ryushe whether to use 1Password, the local credential store, or manual storage.

For local harness notes, write a small pointer file under:

```text
$HARNESS_SHARED_BASE/{program}/credentials/
```

The pointer may include:
- account alias
- email alias/reference
- role and tenant/workspace relationship
- Bitwarden item reference
- created test resources
- cleanup notes

It must not include passwords, cookies, bearer tokens, auth headers, recovery codes, or mailbox credentials.

## Account Naming

Use clear aliases:

```text
acct_a_same_role
acct_b_same_role
acct_low_priv
acct_high_priv_approved
tenant_a_owner
tenant_b_owner
tenant_a_viewer
```

Use program-specific prefixes when multiple hunts are active.

## Handoff To Caller

Return a compact setup card:

```text
program:
target:
accounts:
  - alias:
    role:
    tenant/workspace:
    inbox_ref:
    credential_ref:
resources:
cleanup:
blocked:
safe_to_continue:
```

For `/access-control` and `/idor`, include enough owned-object relationship data to compare horizontal, vertical, tenant, workflow, storage, and GraphQL boundaries without loading secrets.

## Cleanup

Record cleanup steps before handing back:
- resources to delete
- invites/memberships to revoke
- sessions to log out
- test content to remove
- accounts that can remain for future testing

Do not delete accounts or resources if deletion itself is the vulnerability test unless the caller explicitly requested cleanup.
