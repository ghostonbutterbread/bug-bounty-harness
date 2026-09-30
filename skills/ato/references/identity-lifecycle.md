# Identity lifecycle and pre-account takeover

**Status:** active ATO expansion. **Owner:** `/ato`. **Canonical path:** `skills/ato/references/identity-lifecycle.md`. **Supersedes:** identity and email-change material in the retired `prompts/ato-context-pack.md`, `prompts/ato-playbook.md`, and `skills/ato/references/methods.md`. Load when current observations include signup, identifier verification/change, local/federated merge, or recovery-destination changes. `/ato` owns common proof and safety rules; `/password-reset` owns reset mechanics.

## Recognize the binding

- **Unverified account claim.** When signup reserves an address before mailbox proof, follow what happens when its real owned mailbox later verifies, signs in through a trusted IdP, or resets the password. Does the earlier password, linked identifier, or session still enter the *same* newly verified account? The pre-hijacking research distinguishes classic/federated merge, persistent session, trojan identifier, pending email change, and non-verifying IdP variants—choose only transitions the app exposes.[8][9]
- **Identifier comparison mismatch.** Compare the *same owned address or phone* across signup, login, email change, recovery, invite, and IdP linking. Case, Unicode, whitespace, plus aliases, provider-specific dot handling, and phone formatting are hypotheses, not universal equivalences. Look for a stored identity resolved differently by a later proof flow, not cosmetic variation.[4][8]
- **Verification of the wrong pending change.** For two owned pending signups or email/phone changes, compare which recipient, purpose, account, and pending transaction the final link/code actually confirms. Check a canceled or superseded change only once to see whether its old proof can still install a recovery destination. A verification banner or old link opening a page is not the security result.[4][8][9]
- **Email/recovery address change.** Map current session, recent password/MFA proof when required, new-address confirmation, notice to the old address, and the account ID at final confirmation. Ask whether a weaker session or B's inbox installs a recovery path on A. Ordinary verified self-service change is not ATO.[3][7]
- **Local/federated merge.** If social login creates or attaches an account by email, compare the provider's verified-email status and stable issuer/subject with an existing unverified local account. Test whether the local password survives a later legitimate IdP login to the *same* account. Continue in `references/federation.md` for callback and provider binding.[8][12]
- **New-account action on an existing identity.** If a passwordless signup or first-password flow exists, compare whether its final server-side decision verifies a genuinely new owned account or changes an already-existing owned account merely because the request supplies its phone/email and a client-selected workflow state. A reported passwordless-signup path changed an existing account's password; the endpoint name and a `SUCCEEDED` field alone are not proof—read back the owned account's credential state. Route password reset mechanics to `/password-reset`.[31]
- **Verification followed by legacy-account merge.** When a pending email change survives unrelated profile edits, check whether an avatar/profile save confirms a different address than the one proved by an owned mailbox *and* whether a later migration or merge accepts that claim. One disclosed Shopify chain required a target legacy account that had never merged into Shopify ID and had no 2FA; email confirmation plus photo writes preceded a store-to-ID merge and password setup. The confirmation bypass alone was not the takeover proof. Test only analogous owned, eligible account transitions, then read back the resulting central account and login authority.[35]

## Evidence discriminator

Use owned account aliases and inboxes; observe final local account ID, verified identifier, retained login methods, recovery recipient, and active sessions. Merely reserving an address, accepting an alias, or displaying a verified flag is not takeover proof. Route the reset-token and delivery mechanics to `/password-reset`; route a final user/account ID authorization flaw to `/access-control` or `/idor`, and a pending-change race to `/race`.

## Sources

[3] https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
[4] https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html
[7] https://pages.nist.gov/800-63-4/sp800-63b.html
[8] https://www.microsoft.com/en-us/msrc/blog/2022/05/pre-hijacking-attacks
[9] https://arxiv.org/abs/2205.10174
[12] https://openid.net/specs/openid-connect-core-1_0.html
[31] https://hackerone.com/reports/143717
[35] https://hackerone.com/reports/910300
