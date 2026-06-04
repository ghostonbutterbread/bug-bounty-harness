# ATO Playbook

Use this after `/ato` has classified a lane. The goal is to find identity-binding failures with minimum owned-account proof.

## Setup

Use two owned accounts whenever possible:

- Account A: target/victim-owned test account
- Account B: attacker-owned test account

Add external IdP accounts only when the target supports SSO or social login:

- IdP A maps to Account A
- IdP B maps to Account B

Record aliases and destructible status only. Do not store credentials, tokens, reset links, OAuth codes, SAML assertions, or private email content.

## Flow Map

For the selected flow, capture:

- entry URL and method
- account identifier submitted
- proof requested
- transaction or pending state created
- email, IdP, MFA, invite, or session artifact sent
- final confirmation request
- account/session/security setting that changed
- security notification or audit side effect

Mark where server-side binding must happen. Most ATO bugs sit in the final step, not the first step.

## Test Order

1. Run the baseline on Account A and Account B separately.
2. Identify the account-binding fields and proof-binding fields.
3. Choose one mismatch family from the context pack.
4. Send one controlled mutation with owned accounts.
5. Check the resulting account, session, linked identity, email, MFA, invite role, and notifications.
6. Stop on first proof or clear negative result.

## Lane Notes

### Recovery Email and Email Change

Check whether the final confirmation revalidates:

- current session
- current password or recent-auth state
- old email ownership when required
- new email code ownership
- account ID or pending email-change transaction
- duplicate or normalized email collision

Strong signals:

- Account B verifies or installs an email on Account A.
- A recovery email can be added, replaced, or removed without the required proof.
- A pending email verification can be completed by the wrong owned session.

### SSO and Account Linking

Check whether the final callback or link step revalidates:

- OAuth `state` and `nonce`
- stable IdP subject, not just email
- provider, tenant, organization, and domain
- currently logged-in local account
- provider-enabled policy
- pending link transaction
- first-login provisioning state

Strong signals:

- IdP B links to Account A without Account A approval.
- SSO login creates a session for the wrong local account.
- An SSO provider disabled for an account/org can still attach or authenticate.
- A first-login or onboarding flag changes server-side account binding.

### MFA and Recovery Factors

Check whether setup, reset, disable, and recovery actions require the right proof:

- current password or recent auth
- existing MFA or recovery code
- verified email or phone
- admin approval when required
- current account/session binding

Strong signals:

- Account B can add/remove/replace a factor for Account A.
- MFA can be bypassed by stale pending state or alternate login path.
- Recovery code issuance or consumption applies to the wrong account.

### Invites, Teams, and Domains

Check whether invite acceptance binds to:

- invite email
- logged-in account
- organization/domain policy
- IdP tenant
- role assigned by inviter

Strong signals:

- Account B accepts an invite meant for Account A.
- A role or org membership is granted to the wrong owned account.
- SSO/domain enforcement is skipped after invite or account switch.

### Sessions and Security State

Check whether security-factor changes invalidate or update sessions correctly:

- reset should invalidate old sessions when target policy says it should
- email/MFA/SSO changes should not leave stale privileged sessions if reauth is required
- account switch should not carry security pending state across identities

Strong signals:

- stale session completes another account's pending security flow
- security change leaves unauthorized control path active
- desktop/mobile deep link resumes the wrong browser account state

## Reportability Gate

A reportable ATO finding needs:

- exact full URLs and methods
- account aliases and ownership proof
- baseline request/result
- modified request/result with secrets redacted
- final account/session/security state showing wrong binding
- why the verifier did not match the claimed account
- cleanup or rollback status

Negative findings are still useful when they close a hypothesis. Record what was checked and which server-side binding held.

## Handoff Card

Use this when handing off to `/password-reset`, `/access-control`, `/race`, `/csrf`, `/headers`, `/bypass`, or `/single-request-grabber`:

```text
ATO handoff
Program:
Flow:
Full URL(s):
Owned accounts:
External IdP aliases:
Destructible status:
Claim being tested:
Verifier expected:
Observed binding fields:
Mutation family:
Baseline result:
Question for child skill:
Stop condition:
Evidence path:
```
