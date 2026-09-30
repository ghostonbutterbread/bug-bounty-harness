# Invitation and organization identity

**Status:** active ATO expansion. **Owner:** `/ato`. **Canonical path:** `skills/ato/references/organization-identity.md`. **Supersedes:** invite/organization material in the retired ATO context pack, playbook, and method atlas. Load for observed invitation, domain claim, SSO-enforced membership, JIT provisioning, org switch, or role grant. Object-level authorization routes to `/access-control` or `/idor`.

## Follow the grant

- **Invite acceptance.** Trace invitation token, invited address/identity, accepting logged-in account, org/tenant, assigned role, expiry, replacement, and one-time use at the *final* membership grant. Compare owned accounts when policy permits. Auth0's example binds invitation and organization parameters and requires the authenticated email to match the invited address; other applications may intentionally use different semantics.[21]
- **Invite acceptance as authentication.** When an inviter can view or use the invitation confirmation link, check whether acceptance only grants membership to the verified invitee or also logs the clicker into an *existing* account associated with the invited address. A disclosed case allowed an inviter to obtain an existing user's session from their own invitation dashboard. Prove the resulting owned session principal, not just membership or link visibility; never send invitations to non-owned users.[37]
- **Identity versus membership.** An email address, a verified IdP subject, a domain suffix, and an org role are distinct claims. Determine whether the configured IdP tenant/connection, accepted invitation, and server-side membership authorize the issued org session. Test pending/removed/reinvited owned members only when the app exposes those transitions.[12][13]
- **Role and account switch.** Check whether an old invite or another owned session can alter the target account or role at acceptance, and whether legacy password/mobile/API paths bypass an enforced SSO/role policy. A different UI, expected guest account, or intentional cross-device acceptance is not itself ATO.[15][23]
- **SCIM/directory attribute authority.** Where an approved owned tenant can sync users, compare immutable external subject/username, provisioned email, verified domain, local account selected, notification, and reset destination after a profile update. A disclosed SCIM chain kept the existing user's directory username while changing the email to an owned address inside the verified domain, then received password recovery there. Domain verification and a successful sync do not independently authorize changing a different local user's recovery identity. Do not configure or import another organization's directory without explicit approval.[32]

## Evidence discriminator

Prove the resulting server-side account ID, organization, membership, and granted role diverge from the intended authorized identity. If B may accept an invite addressed to A by product design, do not promote that fact without a policy-contrary grant. Route cross-tenant object ownership to `/access-control` or `/idor`, and acceptance races to `/race`.

## Sources

[12] https://openid.net/specs/openid-connect-core-1_0.html
[13] https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
[15] https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/10-Weaker_Authentication_in_Alternative_Channel
[21] https://auth0.com/docs/manage-users/organizations/configure-organizations/invite-members
[23] https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication
[32] https://hackerone.com/reports/3178999
[37] https://hackerone.com/reports/915110
