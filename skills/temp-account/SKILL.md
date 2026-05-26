---
name: temp-account
description: "Create approved temporary owned test accounts for scoped bug bounty workflows using disposable email, browser automation, and password-manager storage."
---

# Temp Account

Use when a hunt needs a new owned test account, especially before destructive, state-changing, access-control, IDOR/BOLA, tenant, role, invite, workflow, upload, delete, or cleanup testing.

This is an account setup router, not a vulnerability testing skill. Return account aliases and setup notes to the caller; keep secrets out of prompts, chat, findings, and reports.

## Load Order

1. Confirm the target program allows account creation, authenticated testing, disposable email, and the intended account count.
2. Resolve `$HARNESS_ROOT` first; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/temp-account-playbook.md`.
4. Check whether the program requires a specific researcher email domain. If it does, use that approved account path instead of disposable email.
5. Load `/agent-email` only when disposable inboxes are allowed for the target.
6. Load `/chromium-test` or another approved browser skill for signup UI control.
7. Store credentials in Bitwarden with `bw` if available; otherwise stop and ask Ryushe which credential store to use.
8. Write only aliases, role/tenant/resource relationships, cleanup notes, and password-manager item references under `$HARNESS_SHARED_BASE/{program}/credentials/`.

## Trigger Points

Use this skill before proceeding when:
- the caller needs more owned accounts, roles, tenants, workspaces, orgs, projects, invites, or disposable resources
- destructive or irreversible actions would touch a normal account
- the test needs delete/update/finalize/publish/share/invite/payment-adjacent boundaries and no temporary account exists
- access-control testing lacks at least two owned account/resource baselines

## CAPTCHA And Verification

- Browser automation may navigate signup, fill forms, and wait for email codes or links.
- Program-required researcher email domains override disposable inbox use.
- If CAPTCHA appears, pause at the browser/manual handoff point and ask Ryushe to complete it unless the program explicitly allows automated solving.
- Do not use CAPTCHA bypasses, solver services, residential proxies, or anti-bot evasion without explicit approval.
- Use `agent-email read ... --wait` for email verification and 2FA codes from owned temporary inboxes only.

## Output Contract

Return:
- program and target domain
- account aliases, not raw usernames/passwords
- inbox alias or email reference
- Bitwarden item reference or credential-store pointer
- role/tenant/resource relationships
- created owned resources
- cleanup requirements
- blockers and manual steps

Never return passwords, cookies, bearer tokens, reset links, private message bodies, or CAPTCHA solution material.
