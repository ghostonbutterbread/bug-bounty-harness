---
name: create-account
description: "Ghost-only workflow for creating approved bug bounty test accounts and saving credential references."
---

# Create Account

Use only when Ryushe asks Ghost to make or prepare a reusable bug bounty test account.

This is Ghost-only account provisioning. Do not hand this skill to Codex/Claude workers. Workers that need disposable inboxes should use `/temporary-email`.

## Workflow

1. Confirm the program and signup target are in scope and account creation is allowed.
2. Check for a site-specific auth flow note under `references/site-flows/` before opening the browser.
3. Use the general/researcher email path Ryushe provides or has approved.
4. Do not invent forwarded aliases. Current generic aliases are `ryushe+ai`, `ryushe+ai1`, `ryushe+ai2`, and `ryushe+ai3` at approved Bugcrowd/HackerOne domains unless Ryushe gives another alias.
5. Use the approved Stealth browser for target signup flows when available.
6. CAPTCHA and Cloudflare prompt solving are allowed for approved setup/testing. Do not use solving for bulk account creation, spam, scraping, rate-limit evasion, denial of service, or disruptive traffic.
7. Ghost/parent may use `/gmail` to read Ghost's mailbox for verification, login, registration, and reset mail. Do not require child agents to use `/gmail`; Ryushe manages forwarding rules.
8. Wait 30-60 seconds for expected mail, refresh/search narrowly, then ask Ryushe if the code still is not available.
9. Store credentials in Bitwarden. Record only account aliases and Bitwarden item references in local notes.
10. Load `/account-management` and record the non-secret account identity: alias, approved email/username, user ID if known, Bitwarden item reference, PwnFox color if mapped, role/tenant, and destructible status.

## Forwarded Login Codes

For approved program email domains, `ryushe+1@...` and `ryushe+2@...` are forwarded to Ghost's mailbox. When creating an account or logging in with those aliases, Ghost/parent retrieves the one-time code or verification email, then provides only the short-lived code to the active browser/login step or child agent if needed.

Only read mail needed for the active verification/login/reset flow. Never expose full message bodies, reset links, mailbox metadata beyond the needed code, or any unrelated email content. Do not pass Gmail access, mailbox sessions, credentials, cookies, or reusable secrets to child agents.

## Account Selection

When an existing account may be available, search Bitwarden by program/site name and approved alias. Use item names and usernames to identify the account, but never expose passwords, tokens, cookies, recovery codes, or private notes.

Destructible status:

- `ryushe+demo@...` accounts are destructible by naming convention.
- `isyphinbots@gmail.com` is an approved destructible account.
- `ryushe+ai`, `ryushe+ai1`, `ryushe+ai2`, and `ryushe+ai3` style accounts are reusable/general test accounts and are not destructible unless stored metadata explicitly says `destructible: yes`.
- Any account without a clear alias or stored destructible metadata defaults to `destructible: no`.

If the test may delete, burn, rate-limit, suspend, or permanently alter an account, use only an account marked destructible. Otherwise stop and ask Ryushe.

## Site Flow Notes

Load only the matching site note:

- Canva: `references/site-flows/canva.md`

If no matching note exists, use the generic workflow and record any unusual auth steps after the run.

## Notes

- Keep personal Ryushe accounts separate from agent accounts.
- General agent accounts are for normal reusable testing.
- If a test will permanently delete or burn an account, create a disposable account instead with `/temporary-email`.
- Treat `ryushe+demo@...` as the reusable destructible-account naming pattern for owned test flows.
- Treat `isyphinbots@gmail.com` as destructible when selected from Bitwarden for owned test flows.
- Never write passwords, cookies, bearer tokens, reset links, recovery codes, mailbox credentials, or private message bodies into chat, prompts, reports, or local notes.
- Use `/account-management` for reusable non-secret user IDs, PwnFox colors, and owned resource IDs created during setup.
