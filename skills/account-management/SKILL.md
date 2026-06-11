---
name: account-management
description: "Record and look up non-secret bug bounty test account, PwnFox lane, and owned resource identifiers."
---

# Account Management

Use when a hunt needs reusable owned-account context: account aliases, user IDs,
roles, PwnFox colors, workspace IDs, document/design IDs, upload IDs, order IDs,
or other object handles tied to Ryushe/Ghost-controlled accounts.

This skill stores identifiers only. Never store passwords, cookies, bearer
tokens, reset links, API keys, recovery codes, private request bodies, or other
secret material.

## Load Order

1. Resolve `$HARNESS_ROOT`; default is `/home/ryushe/projects/bug_bounty_harness`.
2. Resolve `$HARNESS_SHARED_BASE`; default is `/home/ryushe/Shared/bounty_recon`.
3. Open the registry:
   - `$HARNESS_SHARED_BASE/{program}/credentials/account_inventory.json`
4. If the file is missing, initialize it before testing:
   - `python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py init {program}`
5. Read `$HARNESS_ROOT/prompts/account-management-playbook.md` for required fields and handoff format.

## What To Record

- account alias, email/username if approved to store, user ID, role, tenant/workspace, credential reference, destructible status
- PwnFox color to account alias mapping
- owned resource type, resource ID, display name, owner account, full source URL, run/session ID, cleanup/destructible status
- evidence source: browser, Caido, manual note, API response, signup flow, or child-agent output

## PwnFox Proxy Config

Use the registry's `proxy_identity.pwnfox` block instead of guessing header names.
Observed in Ryushe's Caido traffic:

```text
Header name: X-PwnFox-Color
Value format: lowercase color string, for example blue
Caido presence filter: req.raw.cont:"X-PwnFox-Color"
Caido color filter template: req.raw.cont:"X-PwnFox-Color" AND req.raw.cont:"{color}"
```

## CLI

```bash
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py show {program}
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-account {program} --alias primary --email ryushe+ai@example.com --user-id USER_ID --credential-ref "bitwarden:item-name" --pwnfox-color blue --destructible no
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-resource {program} --type design --id DESIGN_ID --name "profile test design" --owner primary --url https://target.example/design/DESIGN_ID --cleanup-needed yes
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py link-pwnfox {program} --color blue --account primary
```

## Routing

- Before `/idor`, `/access-control`, `/jwt-auth`, `/payment-testing`, `/pfp`,
  `/single-request-grabber`, or `/pwnfox` comparisons, load this skill if owned
  account/resource identity is unclear.
- After `/create-account`, browser setup, proxy mapping, document creation,
  upload creation, order/checkout setup, or workspace creation, update the
  registry before handing work to child agents.

## Stop Conditions

Stop and ask Ryushe before recording real secrets, non-owned private data,
personal account details outside the approved test identity, or destructive
cleanup assumptions that are not explicit.
