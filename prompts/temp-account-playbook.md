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
- required researcher email domains or account identity rules
- disposable email is allowed or at least not prohibited
- required account count, role mix, and tenant/workspace/project count
- intended test actions and which ones are destructive
- whether phone, payment, SSO, or manual approval is required

Stop and ask Ryushe if the flow requires payment, phone verification, public posting, messaging real users, bulk creation, abusing anti-abuse controls, or actions outside scope.

## Disposable Inbox

Use `/agent-email`.

Do not use a disposable inbox when the program requires a specific researcher email domain, bug bounty platform alias, customer-provided tenant, SSO identity, or pre-approved account. In that case, stop and ask Ryushe for the approved account path or existing credential reference.

Preferred commands:

```bash
agent-email create
agent-email read <email-or-alias> --wait 90 --interval 3 --limit 10
agent-email show <email-or-alias> <message-id>
```

Use JSON output when available so verification links and codes can be parsed. Read only owned inboxes created for this test.

Do not print mailbox passwords, verification links, reset links, codes, or private message bodies in chat, prompts, findings, or reports.

## Program Email Aliases And Forwarded Codes

Some programs require a bounty-platform researcher email, such as `@bugcrowdninja.com`, instead of disposable inboxes.

Use aliases shaped like:

```text
ryushe+ai-<program>-a@bugcrowdninja.com
ryushe+ai-<program>-b@bugcrowdninja.com
ryushe+ai1@bugcrowdninja.com
ryushe+ai2@bugcrowdninja.com
```

Gmail filters do not support true regex or arbitrary wildcards. Use Gmail to forward broad-but-safe matches, then let the receiving agent inbox/parser do exact regex matching.

Suggested Gmail filter query for relay mail:

```text
("Relayed on behalf of" "to ryushe+ai" "@bugcrowdninja.com")
("code" OR "verification" OR "verify" OR "login" OR "registration" OR "register" OR "forgot password" OR "password reset")
```

Program-specific variant:

```text
("Relayed on behalf of" "<program>" "to ryushe+ai" "@bugcrowdninja.com")
("code" OR "verification" OR "verify your email" OR "login code" OR "registration" OR "forgot password" OR "password reset")
```

Recommended Gmail actions:
- forward to the agent-controlled inbox
- apply a label like `ghost/bugbounty/<program>-codes`
- never send to spam
- keep Ryushe's original copy unless he asks otherwise

After forwarding, parse with real regex in the agent inbox/tooling:

```regex
Relayed on behalf of (?P<sender>[^\s\]]+) to (?P<alias>ryushe\+ai[^\s\]]*@bugcrowdninja\.com)
```

Classify message purpose with subject/body terms:
- code: `code`, `login code`, `security code`, `verification code`, `one-time code`, `OTP`
- email verification: `verify`, `verify your email`, `confirm your email`, `registration`, `register`
- login: `login`, `sign in`, `new sign-in`, `magic link`
- password recovery: `forgot password`, `password reset`, `reset your password`

Do not forward broad personal mail. Keep filters tied to bounty relay phrases, program names, and `+ai` aliases.

## Browser Signup

Prefer the approved Stealth browser for program signup and target-site testing. Use `/chromium-test` or another isolated browser automation skill only when Stealth is unavailable, unsuitable, or the caller specifically needs the Chromium-test/Caido profile workflow.

Default flow:

1. Launch a Stealth browser profile for the program and task when available; otherwise launch an isolated Chromium/Playwright profile.
2. Navigate to the in-scope signup URL.
3. Fill only required signup fields.
4. Use the approved program-required email path, or the disposable inbox if allowed, for verification links or codes.
5. If CAPTCHA or a Cloudflare prompt appears, solve it through the approved browser/solver path when needed for account setup or normal program testing.
6. Finish only non-sensitive onboarding steps needed for testing.
7. Create the minimum private owned resources requested by the caller.

Avoid normal Ryushe browser profiles. Avoid broad profile reuse unless the caller explicitly asks for the same account context.

Stealth and CAPTCHA/Cloudflare prompt solving are acceptable for program workflows. Do not use solving for bulk account creation, spam, scraping, rate-limit evasion, denial of service, or other disruptive traffic.

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
