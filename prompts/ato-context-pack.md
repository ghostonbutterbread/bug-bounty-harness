# ATO Context Pack

Use this after `/ato` has loaded policy and ownership context. Treat examples as hypothesis prompts, not proof or target-specific claims.

## Core Mental Model

Account takeover happens when the application accepts control of one identity proof as control of another account.

Common identity proofs:

- mailbox control
- current password
- reset link, reset code, recovery code, or magic link
- OAuth/OIDC `sub`, SAML NameID, IdP email, or IdP tenant
- MFA device, authenticator enrollment, SMS number, recovery factor, or passkey
- active session, remembered device, or device binding
- invite link, team membership, workspace role, or organization domain
- username, phone number, external account ID, account ID, or user ID

Useful questions:

- Which field says who the user is?
- Which proof says the caller owns that identity?
- Is the binding checked server-side at the final state-changing step?
- Does the app trust a client flag, onboarding state, return parameter, stale session, or cached identity?
- Can two owned accounts make the app link, merge, reset, or verify the wrong identity?

## High-Signal Surfaces

Password and recovery:

- forgot-password request and response
- reset-link generation host, path, locale, redirect, and account identifier
- reset-token redemption and final password-change request
- recovery email add/change/remove
- backup codes, recovery codes, magic links, login codes, and account unlock
- session invalidation after reset

Email and profile security:

- primary email change
- secondary/recovery email forms
- verification-code confirmation
- duplicate email, plus-address, case, Unicode, dot, alias, or normalization behavior
- pending email state and rollback/cancel flows

SSO/OAuth/SAML/OIDC:

- social login and enterprise SSO login
- account linking/unlinking
- first-login provisioning and "create or attach" decisions
- `state`, `nonce`, redirect URI, callback URL, organization/tenant/domain selection
- IdP email versus stable IdP subject binding
- disabled or not-enabled provider behavior
- multiple SSO providers for one local account
- multiple local accounts attempting to link the same IdP identity

MFA and device trust:

- setup, disable, reset, fallback, recovery, and remembered-device flows
- MFA enrollment after SSO first login
- current password or recent-auth prompts
- changing phone/email while MFA is pending
- passkey/WebAuthn registration and removal

Session and account switching:

- login-as, switch workspace, switch account, impersonation, support/admin portals
- stale sessions during email change, SSO linking, password reset, or account merge
- logout and session invalidation after security-factor changes
- deep links that resume auth flows in desktop/mobile apps

Invites and organization identity:

- invite links and role changes
- accepted invite tied to email, session, org, or IdP identity
- domain-claimed orgs and SSO enforcement
- pending member, removed member, and re-invite flows

## Canva-Style SSO Hypothesis Pattern

Use this as a general pattern for targets with Microsoft, Google, enterprise SSO, or similar flows.

Scenario:

- Account A is a normal owned local account.
- Account B is another owned account at the external IdP.
- The target starts an SSO flow, returns through a first-login or onboarding path, then asks for a code or verification step.

Questions to test with owned accounts:

- After the IdP callback, does the target bind the final session to the IdP subject, the IdP email, the currently signed-in local account, or a client-side flow state?
- If a provider is not enabled for the local account or org, does the server enforce that before linking or session creation?
- Are first-login, onboarding, provider-enabled, or needs-code flags accepted from client parameters instead of recomputed server-side?
- Can Account B's IdP identity be started in one browser state and completed against Account A's local session?
- Can multiple SSO providers or repeated attempts cause the wrong account to be linked, merged, or verified?
- Does the final code verification re-check the IdP identity, local account, provider, org, and pending transaction server-side?

Parameters worth noticing, not blindly trusting:

- `first_login`, `firstTime`, `isNewUser`, `newUser`
- `provider`, `connection`, `idp`, `tenant`, `domain`, `org`, `workspace`
- `email`, `login_hint`, `prompt`, `state`, `nonce`, `flow`, `transaction`
- `link`, `link_account`, `signup`, `mode`, `next`, `redirect`, `continue`
- `needs_code`, `verified`, `mfa_required`, `sso_enabled`

Proof requires a server-side result: wrong account session, wrong linked IdP, wrong verified email, wrong org membership, or security-factor change. A parameter name or UI step alone is not enough.

## Mutation Families

Use one family at a time:

- account identifier swap between two owned accounts
- pending transaction ID swap
- email normalization variant
- browser/session swap after starting a flow
- IdP account swap during callback
- provider or tenant mismatch
- onboarding/first-login flag toggle
- stale token or reused verification step
- invite accepted while logged in as another owned account
- link/unlink race or double-submit

Avoid brute force, broad payload lists, and repeated code guessing. The goal is binding confusion, not credential attack.
