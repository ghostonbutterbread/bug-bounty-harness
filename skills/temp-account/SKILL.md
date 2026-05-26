---
name: temp-account
description: "Create approved temporary owned test accounts for scoped bug bounty workflows using disposable email, browser automation, and password-manager storage."
---

# Temp Account

Use when a hunt needs a new owned test account, especially before destructive, state-changing, access-control, IDOR/BOLA, tenant, role, invite, workflow, upload, delete, or cleanup testing.

This is an account setup router, not a vulnerability testing skill. Return account aliases and setup notes to the caller; keep secrets out of prompts, chat, findings, and reports.

## Load Order

1. Confirm the target program allows account creation, authenticated testing, the intended account count, and whether disposable email is prohibited.
2. Resolve `$HARNESS_ROOT` first; default is `/home/ryushe/projects/bug_bounty_harness`.
3. Read `$HARNESS_ROOT/prompts/temp-account-playbook.md`.
4. Prefer a bounty-platform or researcher email alias when it is applicable and available.
5. Use `/agent-email` temporary inboxes when a researcher alias is unavailable, leased, not needed, or the caller explicitly needs an isolated throwaway/risky-lane account, as long as the program does not explicitly prohibit disposable email.
6. If the approved email path uses forwarded relay mail, load `/gmail` for the `+ai` alias and forwarded-code parsing flow.
7. Prefer the approved Stealth browser for signup UI control; fall back to `/chromium-test` or another isolated browser skill only when Stealth is unavailable or unsuitable.
8. Store credentials in Bitwarden with `bw` if available; otherwise stop and ask Ryushe which credential store to use.
9. Write only aliases, role/tenant/resource relationships, cleanup notes, and password-manager item references under `$HARNESS_SHARED_BASE/{program}/credentials/`.

## Trigger Points

Use this skill before proceeding when:
- the caller needs more owned accounts, roles, tenants, workspaces, orgs, projects, invites, or disposable resources
- destructive or irreversible actions would touch a normal account
- the test needs delete/update/finalize/publish/share/invite/payment-adjacent boundaries and no temporary account exists
- access-control testing lacks at least two owned account/resource baselines

## CAPTCHA And Verification

- Browser automation may navigate signup, fill forms, and wait for email codes or links.
- Bounty-platform/researcher email aliases are preferred when applicable and available; temporary inboxes are acceptable fallback accounts when not explicitly prohibited.
- Current forwarded researcher aliases are only `ryushe+ai`, `ryushe+ai1`, `ryushe+ai2`, and `ryushe+ai3` at `bugcrowdninja.com` or `wearehackerone.com`; do not invent program-suffixed aliases unless Ryushe updates forwarding.
- Gmail forwarding filters are broad search queries, not regex. Apply exact parsing after mail reaches the agent inbox.
- CAPTCHA and Cloudflare prompt solving is allowed when needed for approved account setup or normal program testing.
- Do not abuse solving for bulk account creation, spam, scraping, rate-limit evasion, denial of service, or other disruptive traffic.
- Use `agent-email read ... --wait` for email verification and 2FA codes from owned temporary inboxes only.
- Prefer fresh temporary-email accounts for risky lanes such as delete, destructive update, upload abuse, invite/share testing, or cleanup tests.

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
