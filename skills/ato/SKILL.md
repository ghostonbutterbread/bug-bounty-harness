---
name: ato
description: "Route account takeover testing across password reset, recovery, SSO/OAuth, account linking, MFA, email change, session, invite, and identity-binding flows."
---

# Account Takeover

Use for account takeover hypothesis mapping and bounded validation across login, signup, password reset, recovery email, SSO/OAuth, account linking, MFA, email change, session transfer, invite, organization membership, and identity-binding flows.

This is a router skill. The first job is to understand which identity proof the application trusts, then load one focused lane. Do not try to "take over" an account; prove confusion or unauthorized control with owned accounts only.

## Load Order

1. Read scope, owned-account context, `/account-testing-policy`, and the active live-testing policy.
2. Confirm every account, email address, IdP account, workspace, invite, recovery artifact, and resource is owned or explicitly approved.
3. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
4. Read `$HARNESS_ROOT/prompts/ato-context-pack.md`.
5. Classify one lane:
   - forgot-password, reset link/code, recovery code, password change by token -> `/password-reset`
   - email change, recovery email, alternate email, verification code, identity merge -> `$HARNESS_ROOT/prompts/ato-playbook.md`
   - SSO/OAuth/SAML/OIDC, social login, account linking, first-login provisioning -> `$HARNESS_ROOT/prompts/ato-playbook.md`
   - user ID, account ID, org ID, invite ID, membership, tenant binding -> `/access-control` or `/idor`
   - CSRF on login/link/change/recovery actions -> `/csrf`
   - race between verification, linking, reset, invite, or session state -> `/race`
   - host/header/path/method/parser mismatch -> `/headers` or `/bypass`
   - one live browser/proxy request must be captured and safely modified -> `/single-request-grabber`
6. Load `$HARNESS_ROOT/prompts/ato-playbook.md` for full flow mapping, stuck analysis, or report writing.

## Workflow

1. Map the identity claim: email, external IdP subject, username, phone, account ID, organization membership, session, device, recovery factor, or invitation.
2. Map the verifier: password, mailbox control, OAuth state/nonce/code, SAML assertion, MFA, current password, logged-in session, admin approval, or signed token.
3. Identify where the app binds claim to verifier, then test one mismatch with owned accounts only.
4. Compare baseline vs mutation: target account, resulting session, linked identity, verified email, MFA state, invite role, recovery factor, and audit/email side effects.
5. Stop after minimum proof of unauthorized session creation, account linking, email/recovery change, reset, identity merge, or cross-account control.

## Proof Standard

Promote only when evidence shows an attacker-controlled owned identity can create or gain control of a different owned account, link an external identity to the wrong account, change a security factor without required proof, bypass verification, or obtain a session/credential-reset path for the wrong account.

Do not promote UI-only confusion, expected account creation, normal plus-address behavior, harmless onboarding flags, response wording, or caller-owned changes without cross-account or security-factor impact.

## Stop Conditions

Stop before touching non-owned accounts, collecting private account data, brute forcing codes/tokens, bypassing MFA with repeated guessing, sending security emails to non-owned recipients, locking accounts, changing real user security settings, or printing raw passwords, cookies, bearer tokens, reset links, OAuth codes, SAML assertions, MFA recovery codes, or private email bodies.

## Evidence

Write notes under `$HARNESS_SHARED_BASE/{program}/ghost/ato/`.

Record full URLs, methods, auth state, owned account aliases, IdP aliases, destructible status, lane, baseline result, mutation, resulting account/session binding, security-email side effects, loaded child skills, cleanup, and stop condition.

Never record raw passwords, cookies, bearer tokens, reset links, reset tokens, OAuth authorization codes, SAML assertions, ID tokens, refresh tokens, MFA secrets, recovery codes, mailbox credentials, or private email bodies.
