# Factors, sessions, and alternate clients

**Status:** active ATO expansion. **Owner:** `/ato`. **Canonical path:** `skills/ato/references/factors-sessions.md`. **Supersedes:** MFA/session material in the retired ATO context pack, playbook, and method atlas. Load when the app exposes factor enrollment/recovery, remembered devices, passkeys, account switching, logout, or client-specific auth behavior. Reset-token mechanics remain with `/password-reset`.

## Factor and challenge binding

- **Step-up versus management.** Compare the proof required to log in with the proof required to enroll, replace, disable, recover, or remove a factor, generate backup codes, or change a recovery phone/address. Is the active session alone enough where recent or existing-factor proof is required? NIST assurance requirements are a benchmark for systems to which they apply, not an automatic mandate for every consumer app.[3][5][7]
- **Incomplete MFA session.** After only the first login stage, see whether a protected action or alternate client accepts the pending session. Compare web/mobile/API/recovery paths the product actually exposes. An intermediate cookie or MFA UI alone is not a bypass; the protected server-side operation is the discriminator.[6][15]
- **Challenge or recovery code confusion.** With owned A/B sessions and valid owned codes, check account, purpose, pending transaction, device/session, expiry, reuse, and old-code behavior after replacement. Avoid guessing or repeated invalid attempts; confirm a wrong-account factor change or authenticated result.[5][6][7]
- **Factor enrollment as a route into another account.** When one request enrolls a factor and another accepts a factor-only login, check the account ID bound at both steps with two owned accounts. A disclosed chain required the target's user ID to be known and its account to have *no factor enrolled*; an owned factor was attached to that account and its valid code then accepted as login proof without a matching password/session. Use only the ID of an owned account lacking MFA. Enrollment alone or a successful-looking verification response is not takeover without the final owned-account session read-back.[38]
- **Support-assisted factor or account recovery, if exposed.** Identify the published identity checks, staff approval boundary, account selected, and resulting factor/reset binding. A mere support contact option is not a vulnerability; require evidence that a weaker or wrong-account proof changes an owned account's security state. Do not initiate a staff interaction, impersonate another user, or change security settings without explicit program permission and disposable owned accounts.[1][5]
- **Passkey/WebAuthn.** During registration and login, follow challenge, RP ID/origin, user-verification requirement, credential ID/user handle, and intended account. For changes to credential inventory, inspect authorization to bind or remove the authenticator. A shared device or synced passkey is not misbinding; show an owned credential authenticating as the wrong owned account or being registered without required account proof.[7][16]

## Session continuity and client parity

- **Pre/post-auth rotation and account switch.** Compare the credential accepted before login/step-up with what is authoritative afterward. A preexisting transferable session must not silently acquire account authority; an unchanged ancillary cookie is not evidence. Try a bounded A→B account switch during a pending email, factor, or link transaction and read back the server-side target.[14]
- **Cross-domain session handoff.** If login issues a one-time transfer credential for another first-party origin, trace how the destination is validated *before* issuance and whether an attacker-controlled owned destination can receive a usable credential despite a trusted-domain check. A disclosed chain combined a regex host-validation flaw with replay of such a transfer token. Test only owned destinations and stop at minimal proof of a wrong-domain credential and resulting owned-account session; an open redirect without usable authority is not ATO.[34]
- **Logout, timeout, and security transitions.** Compare one protected request from an owned second client after logout or intended timeout, and the product's stated behavior after password/factor change. Browser back-button content is not proof. RFC 9700 says refresh-token revocation on password change is optional for authorization servers, while public-client refresh tokens require replay protection through rotation or sender constraint; do not call any surviving token ATO without the product's revocation promise and a usable unauthorized path.[1][10][19][24]
- **Remembered device and alternate client.** Check whether device trust or an old refresh/API token survives account switch, factor removal, or explicit device revocation unexpectedly. Follow the same claim and verifier through actual web, native/deep-link, GraphQL/API, legacy, or support/admin routes. If an API accepts a client-supplied account/org ID or `verified`/recovery field, read back the exact owned target; a writable-looking field or different prompt is only a lead.[6][15][23]

## Evidence discriminator

Read back factor inventory, session principal, protected server action, account ID, and audit/security notifications. Stop escalation after minimal proof for a path, but continue other independent plausible flows. Route reset delivery/token details to `/password-reset`, object authorization to `/access-control` or `/idor`, and browser-driven request mutation to its specialist.

## Sources

[1] https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
[3] https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
[5] https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
[6] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/11-Multi-Factor_Authentication
[7] https://pages.nist.gov/800-63-4/sp800-63b.html
[10] https://www.rfc-editor.org/rfc/rfc9700.html
[14] https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
[15] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/10-Weaker_Authentication_in_Alternative_Channel
[16] https://www.w3.org/TR/webauthn-3
[19] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/06-Logout_Functionality
[23] https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication
[24] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/06-Session_Management/07-Session_Timeout
[34] https://hackerone.com/reports/3723458
[38] https://hackerone.com/reports/810880
