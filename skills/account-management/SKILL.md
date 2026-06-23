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

- account alias, email/username if approved to store, user ID, role, tenant/workspace, credential reference, auth seed reference, destructible status
- PwnFox color to account alias mapping
- owned resource type, resource ID, display name, owner account, full source URL, run/session ID, cleanup/destructible status
- evidence source: browser, Caido, manual note, API response, signup flow, or child-agent output

## Authentication Resolution

For named accounts or colors, resolve auth in this order:

1. Read the account inventory for the selected alias/color and use the current
   non-secret references: `auth_seed_ref`, `credential_ref`,
   `auth_refresh_source`, `auth_refresh_hint`, `auth_check_url`, and
   `auth_host_filter`.
2. Try the current stored auth seed/session or secret-store reference in the
   agent lane.
3. Use the resolver script instead of hand-rolling host/proxy decisions:
   ```bash
   python3 $HARNESS_ROOT/skills/account-management/scripts/auth_resolver.py resolve \
     --program {program} \
     --account blue \
     --json
   ```
   The resolver reads the proxy route table to decide whether this runtime can
   query Ryushe's proxy directly, must use one-shot Hoster SSH, or must fail
   closed.
4. If stored auth fails and the account record explicitly allows it, use
   Ryushe's proxy only as a source lookup or named-account auth-refresh source.
5. If Ryushe's proxy cannot be reached, has no matching account evidence, or
   cannot refresh the selected account, load `/bitwarden` and use the recorded
   Bitwarden credential reference as fallback.

After a proxy-derived refresh, active testing must use the agent MITM lane. Do
not test through Ryushe's proxy just because the account evidence came from
there.

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
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-account {program} --alias primary --email ryushe+ai@example.com --user-id USER_ID --credential-ref "bitwarden:item-name" --auth-seed-ref "auth-seed:/secure/path/primary.json" --auth-check-url "https://target.example/account" --auth-host-filter "target.example" --pwnfox-color blue --destructible no
python3 $HARNESS_ROOT/skills/account-management/scripts/auth_resolver.py resolve --program {program} --account blue
python3 $HARNESS_ROOT/skills/account-management/scripts/auth_resolver.py refresh-from-ryushe-proxy --program {program} --account blue --host-filter target.example
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
