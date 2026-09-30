# Federated login and identity linking

**Status:** active ATO expansion. **Owner:** `/ato`. **Canonical path:** `skills/ato/references/federation.md`. **Supersedes:** SSO material in the retired ATO context pack, playbook, and method atlas. Load when the app actually uses OAuth/OIDC, SAML, social login, enterprise SSO, IdP provisioning, or link/unlink. Common scope/proof rules live in `/ato`.

## OAuth/OIDC and link transactions

- **Login or link CSRF.** Identify whether the callback is for login or attaching an IdP to an already authenticated local account. Check transaction-bound CSRF protection (`state`, enforced PKCE, or an applicable OIDC nonce), session, and pending purpose. A missing `state` string alone is not proof if another effective protection is in force; prove which local account gets the resulting session or link.[10][18][26]
- **Code and redirect destination.** Compare registered `redirect_uri`, trusted-origin open redirects, app deep links, and PKCE verifier binding. OAuth security guidance calls for precise redirect matching, while the August 2026 browser-app BCP requires PKCE for browser-based public clients using the code grant and redirect-URI CSRF protection. Test only with owned callback endpoints; a permissive-looking parameter without code/token leakage is a lead, not ATO.[10][17][26]
- **Authorization-code consumption and expiry.** In an exposed OAuth code-exchange flow, compare one successful redemption with a single owned-code replay and the documented expiry; check that the *code record's* expiry, not the lifetime of credentials it may mint, controls exchange. A Mozilla report found both missing consumption and a wrong expiry-column check. A reused code is security-relevant only if it mints a usable token/session for the intended owned identity; never collect another user's code.[33]
- **Multiple IdPs or tenants.** Verify issuer, audience/client, expected token endpoint, callback, and transaction stay together across providers. If discovery/dynamic metadata is involved, compare it with the configured trusted connection; do not register or repoint an organization's IdP without explicit authorization. `login_hint`, claimed email domain, or client-supplied provider label is not tenant authorization.[10][11][25]
- **ID token and UserInfo.** Check validated issuer, signature, audience, nonce, lifetime, and stable `sub`; a UserInfo response's `sub` must match the ID token's. OIDC identifies a user by (`iss`, `sub`), not by an email claim that may change or fail to be unique. Email verification alone does not authorize linking an existing local account.[12][20]
- **Link, unlink, and first-login provisioning.** Compare an already signed-in local account, an unlinked IdP, an IdP linked to another owned account, disabled connection policy, and pending onboarding state. Does B's IdP attach to A without proof of both identities? Does an earlier local password or linked method survive a later merge? Only an actual wrong-account link/session or persistent control path establishes impact.[8][12][20]

### When a callback has a separate code/onboarding step

Follow the IdP subject and tenant, local session, provider-enabled policy, and pending transaction through the **final** code verification. Observe whether `first_login`, `provider`, `connection`, `needs_code`, `verified`, or `link` are server-derived facts or just client flags; do not blindly mutate a wordlist. With owned identities, compare starting B's IdP flow in one browser state and completing in A's local session, then read back the resulting linked identity. This generalizes the prior ATO context pack's first-login scenario without treating any one product as a default target.[8][12][20]

## SAML and enterprise identity

- **Assertion consumption.** Determine which signed assertion the SP actually uses and whether signature/key, audience, recipient/destination, time validity, replay, and (for SP-initiated flows) request correlation are enforced. A parser may validate one element but consume another. An explicitly supported unsolicited IdP-initiated flow need not carry `InResponseTo`; assess its own safeguards rather than marking absence alone as ATO.[13][22]
- **Principal and tenant mapping.** Identify the selected NameID format, its stability, IdP connection and tenant, email claim, JIT provisioning, and locally linked methods. A valid assertion for an owned tenant B must not grant owned tenant A's identity or membership. If SSO is required, compare only the observed alternate login/invite routes for a real policy bypass, not a different UI prompt.[12][13][15]
- **SAML transaction/tenant selectors.** If `RelayState` or an IdP entity ID chooses a destination or tenant, compare the exact canonical identity and state stored across subsequent sign-in attempts. Disclosed cases involved a persistent `RelayState` redirect during later OAuth sign-in and an IdP entity-ID collision after whitespace normalization; the latter required user interaction and does not imply a zero-click tenant takeover. Trace only owned IdP/tenant flows and demonstrate a wrong grant or sensitive value reaching an owned destination—not merely a redirect or differently formatted name.[36][39]

## Evidence discriminator

Record the validated provider/tenant and resulting local account ID, linked provider subject, session principal, retained login methods, and security notifications. A successful IdP response or client-side flag without wrong server-side binding is not ATO. Route CSRF, header/redirect, and access-control mechanisms to their specialist skills when that is the main question.

## Sources

[8] https://www.microsoft.com/en-us/msrc/blog/2022/05/pre-hijacking-attacks
[10] https://www.rfc-editor.org/rfc/rfc9700.html
[11] https://www.rfc-editor.org/rfc/rfc9207.html
[12] https://openid.net/specs/openid-connect-core-1_0.html
[13] https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
[15] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/10-Weaker_Authentication_in_Alternative_Channel
[17] https://www.rfc-editor.org/info/rfc8252
[18] https://portswigger.net/web-security/oauth
[20] https://auth0.com/docs/manage-users/user-accounts/user-account-linking/link-user-accounts
[22] https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
[25] https://openid.net/specs/openid-connect-discovery-1_0.html
[26] https://www.rfc-editor.org/rfc/rfc10017.html
[33] https://hackerone.com/reports/3734676
[36] https://hackerone.com/reports/1923672
[39] https://hackerone.com/reports/976603
