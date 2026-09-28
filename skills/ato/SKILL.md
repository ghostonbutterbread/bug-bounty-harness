---
name: ato
description: "Route account takeover testing across signup, recovery, SSO/OAuth, account linking, MFA, email change, sessions, invites, and identity-binding flows."
---

# Account Takeover

Use for account takeover hypothesis discovery and bounded validation. The central question is **which identity claim is accepted, which proof is required, and where the application binds them at the final state-changing step**. Use only owned or explicitly approved identities. This skill is an idea map and router, not a fixed checklist or an instruction to load every reference.

## Start from the app

1. Read `general-security-testing-policy`, scope, owned-account context, `/account-testing-policy`, and `live-testing-policy` before live action. Check `~/Shared/scopes/{program}/`, then `~/Shared/bounty_recon/{program}/scope/`; use `/pullscope` if needed. If no scope exists, record `no scope` as the policy requires.
2. Observe the current login and account flows directly before reading broad prior hunt state. Notice every entry point, identity claim, proof, pending transaction, final confirmation, session/account result, and notification. Use the ideas below to recognize possibilities while exploring; they do not limit what may be tested.
3. For **each plausible hypothesis** exposed by the application, open the matching focused reference or specialist only when its detail helps the next decision. More than one lane can fit a flow. Revisit the idea map as new behavior appears, and reconcile plausible untested flows before calling coverage complete. There is **no cap on ideas or tests**; scope, ownership, rate, safety, and evidence govern each action.
4. Query prior target memory only after current observations give a specific flow, URL, account relationship, or hypothesis. Do not preload the old context pack, the full source catalog, or every specialist.

## Idea map — signal → binding question → where to expand

- **Signup, verification, alias, or email/phone change:** Can an unverified or pending identifier, normalized alias, or old verification step become proof for the wrong account? → `references/identity-lifecycle.md`.
- **Password reset, recovery link/code, or magic login:** Does delivery, token purpose, recipient, final account, or session revocation disagree? → `/password-reset` and its `references/ato-patterns.md`. Do not duplicate reset payload patterns here.
- **SSO, social login, or account link/unlink:** Does a valid IdP proof attach to the wrong local identity, provider, tenant, or transaction? → `references/federation.md`.
- **MFA, recovery factor, passkey, or remembered device:** Can factor setup, fallback, challenge completion, or removal occur under weaker or wrong-account proof? → `references/factors-sessions.md`.
- **Login session, account switch, logout, desktop/mobile/API route:** Does prior or alternate-client state retain or acquire the wrong account's authority? → `references/factors-sessions.md`; load the relevant specialist when the main boundary is session or access control.
- **Invite, organization, domain claim, role, or JIT membership:** Which identity, tenant, invite, and role is the final grant bound to? → `references/organization-identity.md`; route object/tenant authorization to `/access-control` or `/idor`.
- **Cross-cutting mismatch at any flow:** Browser request vs server decision, pending transaction vs current session, method/parser/header difference, CSRF, or race can affect the above. Route the *observed* mechanism to `/csrf`, `/race`, `/headers`, `/bypass`, or `/single-request-grabber` as appropriate. Do not treat the mechanism as ATO without account/security-factor impact.

References expand recognition signals into account/proof/transaction questions and evidence thresholds; they are **not mandatory all-at-once reads**. For a complex flow or handoff, load `references/flow-handoff.md` only when its map or template helps.

## Testing and proof

- Map claim (email, subject, phone, account ID, tenant, invite, device), verifier (password, mailbox, IdP assertion, MFA, current session, admin approval), pending transaction, and final server-side binding.
- Establish a valid baseline, then compare bounded mismatches using owned accounts and the least disruptive fixtures. Check the *resulting server-side* account, linked identity, factor, membership/role, and audit/email side effects; record negative results and continue other plausible hypotheses. A negative result or one successful proof does not exhaust independent flows. Stop escalating a proven path at minimum safe evidence.
- Promote only reproducible unauthorized control of another owned account, wrong-account session/link/reset, security-factor change without required proof, or unauthorized role/membership. UI-only confusion, expected creation, harmless aliases, client flags, response wording, or caller-owned changes without cross-account/security-factor impact are leads, not ATO.

## Stop conditions and evidence

Stop before touching non-owned accounts/resources or private data, brute-forcing codes/tokens, repeated MFA guessing, sending security mail to non-owned recipients, lockouts/inbox flooding, or irreversible security changes to a valuable account. Program rules and live-testing policy always prevail.

Write evidence under `$HARNESS_SHARED_BASE/{program}/ghost/ato/`: full URLs/methods, auth state, owned aliases and fixture status, hypothesis and loaded lane, redacted baseline/mutation, resulting binding and notifications, cleanup, and stop condition. Never record raw passwords, cookies, bearer/reset tokens or links, OAuth codes, SAML assertions, ID/refresh tokens, MFA secrets/recovery codes, mailbox credentials, or private email bodies.
