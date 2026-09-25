# ATO method atlas

**Status:** active research reference. **Owner:** BBH `/ato`. **Canonical path:** `skills/ato/references/methods.md`. **Supersedes:** none. **Research snapshot:** 2026-09-25. This is a hypothesis map, not a fixed test list or permission to probe a target. The `/ato` router, program scope, and live-testing/account policies control execution. References describe classes of failure, not claims that any particular application is vulnerable.

## How to use this atlas

1. Observe the real entry point, callback, final state-changing step, alternate channels, and notification/audit effects. Use two owned, explicitly authorized accounts and their owned inboxes/IdP identities; set up a disposable fixture when a security factor must change. Never touch an unknown user's account, guess someone else's token/code, or create unsolicited emails.
2. Write a five-part hypothesis: **identity claim** → **proof/verifier** → **pending transaction** → **server-side binding at completion** → **resulting account/session/security state**. Compare a normal baseline with *one* bounded, controlled mismatch. Route reset, access control, CSRF, race, headers, and bypass work through their focused skills.
3. Promote only demonstrated server-side cross-account control or a concrete equivalent security-factor change. A redirect, response discrepancy, unverified field, or missing generic hardening is a lead, not ATO. Record negative binding checks too. Redact passwords, tokens, session cookies, authorization codes, assertions, private mail, and recovery secrets.

## 1. Account creation, proof of address, and pre-account takeover

- **Claim before proof.** Compare signup with verification pending, login, reset, email-change, and social login for the same *owned* mailbox.[4][8] Does an unverified signup reserve or link that address? Does later mailbox verification grant access to an attacker-prepared account or merge two identities? After a legitimate owner verifies or federates the identity, does an earlier owned password, linked identifier, pending change, or session still access the *same* account?[8][9] The pre-hijacking research identifies classic/federated merge, unexpired session, trojan identifier, unexpired email-change, and non-verifying IdP patterns; test the *observed* flow, not all patterns reflexively.[8][9]
- **Identifier canonicalization and namespace collision.** Compare case/Unicode normalization, plus aliases, provider-specific dot behavior, whitespace, phone formatting, and distinct IdP email claims across signup, verification, login, recovery, and account linking.[4] Treat provider-specific transformations as hypotheses, not universal email equivalences.[4] Require a wrong-account login, wrong recipient/proof binding, or unauthorized merge—not simply two syntactically different addresses being accepted.[4][8]
- **Verify-the-wrong-transaction.** Start two owned pending email/phone changes or signups and ask whether an old verification link/code, a different session, or a client-supplied account ID can complete the other transaction.[4][8] Check that confirmation binds recipient, purpose, account, pending change, and expiry; a verification banner alone proves nothing.[4][8] If a change is canceled or superseded, check once whether its original link can still install the recovery destination.[8][9]
- **External IdP takeover of an unverified local identifier.** If first-time social/enterprise login auto-merges by email, compare verified vs unverified IdP email claims and stable provider identities; ask whether the local account requires separate proof or explicit linking.[8][12] Some IdPs do not assert mailbox control for all email claim shapes.[8][12]

## 2. Password reset, magic links, and recovery

- **Reset request to delivery split.** Identify which parsed identifier selects the account and which recipient receives the link/code.[1][2] With owned addresses, compare alternate JSON shapes, duplicate/form/list parameters, and normalization only where the observed parser supports them. A meaningful result is a token for Account A delivered to B's owned inbox or a final reset changing the wrong owned account; see `/password-reset`'s concrete pattern reference.[1][2]
- **Reset URL construction and leakage.** Check whether untrusted Host/Forwarded/Origin/redirect parameters alter the *received* link host or post-click code destination; use an owned callback.[1][2] Check Referrer leakage, redirect chains, and logs only to the minimum needed.[1][2] A reflected header without an actual token-bearing email or exfiltration path is not ATO.[1][2]
- **Token binding and lifecycle.** For owned tokens, compare account and purpose binding, expiry, one-time redemption, older-token validity after reissue or password change, and final form fields that may select an account separately from the token.[1][2] A fresh unused token inside its validity window is normal; check server-side enforcement rather than decoding or guessing token contents.[1][2] Compare magic-link/login, signup-confirmation, invite, and recovery purposes only when the application actually shares a token or transaction system.[1][4] Do not brute-force codes or flood inboxes.
- **Recovery-factor substitution.** Map recovery email/phone, backup code, support-assisted recovery, and magic-link paths as equivalent or weaker proofs.[3][5][7] Ask whether a newly added factor, changed address, old session, or alternate factor can reset a different account without required reauthentication and notifications.[3][5][7]
- **Reset side effects.** Record whether reset or factor change rotates/invalidates existing sessions and remembered devices according to the product's policy; lingering sessions are especially relevant when they can finish a queued security change.[1][14] Lack of universal logout alone is not automatically an ATO finding: RFC 9700 says authorization servers *may* revoke refresh tokens on password change, while public-client refresh tokens need replay detection through rotation or sender constraint.[10]

## 3. MFA, passkeys, and remembered devices

- **Step-up gap.** At login, password reset, factor enrollment/removal, backup-code generation, sensitive account changes, and recovery, compare required proof and recent-auth state.[5][6][7] Reusing a session or switching to another supported login route must not silently bypass a required factor.[5][6] Prefer one controlled transaction per route; no OTP guessing.[5][6]
- **Pending challenge swap.** With owned Account A/B browser sessions, see whether an MFA transaction or verification code is bound to the initiating account, purpose, device/session, and expiry at final redemption.[5][6] An MFA form can be present while a downstream API accepts a pre-MFA session for protected operations; prove access to a protected action rather than merely an intermediate cookie.[6][15]
- **Factor registration/recovery.** Check existing-factor proof when registering a new authenticator/passkey, changing phone/email, resetting MFA, adding backup methods, or deleting the last factor.[5][7] Verify the server-side factor inventory and security notifications; an attacker-owned factor attached to a different owned account is strong evidence.[5][7]
- **Remembered-device and alternate clients.** Compare first-party web/mobile/desktop/API sessions, refresh-token grants, and remembered-device state. Determine whether a device trust flag survives account switch, password/factor change, or revocation unexpectedly. Do not infer bypass merely because one channel has a different UI.[6][14][15]
- **WebAuthn binding.** For passkey registration and login, map relying-party ID/origin, challenge freshness, user verification requirement, credential-to-user binding, and registration or removal authorization.[16] A forged UI label or client flag is not proof; an owned credential authenticating as another owned account is.[16]

## 4. OAuth/OIDC, social login, and account linking

- **Login CSRF or link CSRF.** Verify the transaction's CSRF protection (`state` or correctly bound PKCE, as applicable), local browser binding, and purpose (login vs link); try only controlled cross-session or cross-account completions.[10][18] Absence of `state` alone is not proof of a flaw if PKCE supplies the required protection.[10] A successful IdP callback is not enough: inspect which local account receives the session or external identity.[10][18]
- **Code/redirect interception.** Map exact registered `redirect_uri`, open redirects on a registered origin, wildcard/subdomain behavior, app deep links, and PKCE verifier binding.[10][17][18] OAuth best current practice calls for precise redirect matching and PKCE; the August 2026 browser-app BCP requires PKCE for browser-based public clients using the authorization code grant and requires CSRF protection at their redirect URI.[10][26] A token/code reaching an attacker-controlled owned endpoint is the relevant evidence, not permissive-looking parameters by themselves.[10][18]
- **Issuer/client/tenant mix-up.** For multiple IdPs, authorization servers, enterprise tenants, or client registrations, confirm issuer, audience/client ID, intended redirect endpoint, and transaction are checked together.[10][11][12] If IdP discovery or dynamic federation metadata is involved, verify issuer and endpoints correspond to the configured trusted connection; don't register or repoint a real organization's IdP for a test.[25] Do not accept a `login_hint`, email-domain choice, or client-supplied provider label as an authorization fact.[10][12] RFC 9207 specifically addresses authorization-server mix-up by conveying an issuer identifier.[11]
- **ID-token and UserInfo identity binding.** Confirm signature and expected issuer, audience, nonce, lifetime, and stable `sub` are validated, and the local account mapping includes issuer/tenant as necessary.[12] If UserInfo is used, its `sub` must match the ID token's `sub` before consuming other claims.[12] The stable OIDC identity is the (`iss`, `sub`) pair; `email` is not a guaranteed unique account key even when `email_verified` reports past control.[12] Do not merge on unverified or changeable email alone; separate email verification from authorization to link an existing local account.[12][20]
- **Link/unlink and first-login provisioning.** Compare an already logged-in local account, an unlinked IdP identity, one IdP identity already linked elsewhere, disabled provider policy, and pending first-login state.[8][20] Ask whether the callback links B's IdP to A without A's own proof, or whether unlinking/reauthorizing leaves a persistent takeover path.[8][10][20] A linking ceremony needs proof of both controlled identities; an OAuth callback alone does not authorize linking to whichever local account is open.[20]
- **OAuth grant scope isn't local account authority.** A valid token for a provider user proves what that provider asserted for that client; it does not by itself prove ownership of a preexisting local account, an enterprise tenant, or a workspace role.[10][12]

## 5. SAML and enterprise identity

- **Assertion validation.** Confirm trusted IdP signature and signed element, expected audience/recipient/destination, time validity, `InResponseTo` for SP-initiated transactions, and rejection of replay or mismatched pending request.[13][22] XML signature wrapping is a parser/selection hazard when the verified assertion is not the one consumed.[13] Do not treat missing `InResponseTo` alone as a defect in an explicitly supported unsolicited/IdP-initiated flow; that flow has different safeguards and weaker login-intent protection.[13][22]
- **NameID, email, tenant and JIT mapping.** Ask which IdP principal identifier and tenant map to the local user, and whether the selected NameID format is stable enough for that binding; compare unverified or changeable email claims, multiple enterprise IdPs, Just-in-Time creation, provisioning, and locally linked password accounts.[12][13] Test only with IdP accounts and orgs the operator owns. A valid assertion for tenant B must not grant tenant A's identity or membership.[13]
- **SSO enforcement across routes.** Check invited users, legacy password login, mobile endpoints, support/impersonation portals, and account-switch flows for the same server-side identity policy.[13][15] A weaker alternate channel matters only when it creates an unauthorized owned-account session or materially bypasses a required security boundary.[15]

## 6. Sessions, account switching, and alternate channels

- **Session fixation and rotation.** Compare pre-auth vs post-auth session identifiers, login after a reset, privilege/role change, and account switch.[14] A session token chosen or held before authentication must not become an unauthorized authenticated session without appropriate renewal and binding.[14]
- **Logout, revocation and stale pending state.** Check current/all-device logout behavior, old refresh/API tokens, pending email/MFA/link transactions, and session invalidation after a sensitive change.[14][19] After an intended timeout or logout, one protected server request from an owned separate client distinguishes actual authorization from cached UI; an IdP session and an app session can have separate termination semantics.[19][24] Use server-side actions as evidence, not browser cache or a displayed account name.
- **Client inconsistency.** Follow the same claim and verifier through web, mobile, desktop deep link, GraphQL/API, legacy endpoints, and admin/support flows that exist in the target.[15][23] Compare actual server decisions, including a supplied account/org ID or security-state field at the final API write; do not bulk-enumerate routes or assume a different prompt is weaker authentication.[15][23]
- **Cross-account browser state.** Begin a flow as owned A, switch to owned B, then attempt one final step. Observe whether the pending transaction and target account are server-bound or silently inherited from a stale browser tab, service worker, OAuth callback, or account-switch state.[10][14]

## 7. Invitations, organizations, and role binding

- **Invite acceptance.** Map token, invited email/identity, accepting logged-in account, org/tenant, role granted by inviter, expiry, and one-time use.[21] Compare acceptance with each of two owned accounts. Auth0's example invitation system requires the authenticated email to match the invited address and carries the organization and invitation ticket into the auth flow; other products may choose different semantics.[21] An invite sent to A being accepted into B can be valid product behavior; the impact threshold is a role or membership granted contrary to the application's policy or another account's authority.
- **Domain claim and SSO policy.** Distinguish possession of an email address, membership in an organization, and IdP tenant/role authorization. Test pending invite, re-invite, removed member, external collaborator, and first-login enrollment only where the target exposes those transitions. A public domain suffix is not proof of org authorization.[12][13]
- **Role/state transition.** Reconfirm authorization at the final invite acceptance, account-link, org-switch, and membership mutation step. If the main defect is object ownership or a race, route to `/access-control`, `/idor`, or `/race` rather than treating every authorization bug as ATO.

## Triaging and proof

- **High confidence:** B's controlled proof produces A's authenticated session, A's password reset, an attacker-controlled credential/factor linked to A, or unauthorized membership/role on A's owned org. Preserve redacted baseline and mutation, account aliases, resulting *server-side* identity, notification/audit events, and cleanup.
- **Lead only:** different error wording, link accepted by the browser but not the server, policy recommendation unmet without exploitability, account creation with no victim control, harmless email alias behavior, or a stale page displaying A while requests authorize as B.
- **Stop:** non-owned users/IdPs/mailboxes, brute force, token theft outside owned infrastructure, lockout/flooding, third-party data, or irreversible factor changes on a valued account. Program restrictions always prevail.

## Sources

[1] https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
[2] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/09-Weak_Password_Change_or_Reset_Functionalities
[3] https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
[4] https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html
[5] https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
[6] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/11-Multi-Factor_Authentication
[7] https://pages.nist.gov/800-63-4/sp800-63b.html
[8] https://www.microsoft.com/en-us/msrc/blog/2022/05/pre-hijacking-attacks
[9] https://arxiv.org/abs/2205.10174
[10] https://www.rfc-editor.org/rfc/rfc9700.html
[11] https://www.rfc-editor.org/rfc/rfc9207.html
[12] https://openid.net/specs/openid-connect-core-1_0.html
[13] https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
[14] https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
[15] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/10-Weaker_Authentication_in_Alternative_Channel
[16] https://www.w3.org/TR/webauthn-3
[17] https://www.rfc-editor.org/info/rfc8252
[18] https://portswigger.net/web-security/oauth
[19] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/06-Logout_Functionality
[20] https://auth0.com/docs/manage-users/user-accounts/user-account-linking/link-user-accounts
[21] https://auth0.com/docs/manage-users/organizations/configure-organizations/invite-members
[22] https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
[23] https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication
[24] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/07-Session_Timeout
[25] https://openid.net/specs/openid-connect-discovery-1_0.html
[26] https://www.rfc-editor.org/rfc/rfc10017.html
