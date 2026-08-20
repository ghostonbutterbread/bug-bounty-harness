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
2. Resolve `$HARNESS_SHARED_BASE`; default is `/home/ryushe/Shared/web_bounty`. Retired registry tombstones must be treated as errors, not empty inventories.
3. Open the registry:
   - `$HARNESS_SHARED_BASE/{program}/credentials/account_inventory.json`
4. If the file is missing, initialize it before testing:
   - `python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py init {program}`
5. Read `$HARNESS_ROOT/prompts/account-management-playbook.md` for required fields and handoff format.

## What To Record

- account alias, global principal tier (`admin` = owner-equivalent, `user`; anonymous has no account record), email/username if approved to store, user ID, role, tenant/workspace, lifecycle, non-secret program-specific capability/resource labels and organization tier/plan access, browser-lease eligibility, credential reference, auth seed reference, destructible status
- `testing_role: idawr` for a reusable owned second-account pool used in IDOR/BOLA comparisons. Use stable aliases such as `idawr-<color>` for approved `ryushe+ai*` identities; the alias is a registry label, not an email rename.
- linked login identities (Google SSO, social login, etc.): provider, approved non-secret handle/ID, link status, and evidence source; never OAuth codes/tokens, cookies, or provider credentials
- connected integrations: provider, non-secret installation/workspace/connection ID, approved linked social/account handle or ID, connection status, visible non-secret capability labels, and evidence source
- one optional per-program `integration-profile`: an existing owned account
  designated as the central account for explicitly requested integrations. It
  is a non-secret alias/status/source record, not a new email, credential, or
  permission to select a different account silently.
- PwnFox color to account alias mapping
- owned resource type, resource ID, display name, owner account, full source URL, run/session ID, cleanup/destructible status
- evidence source: browser, Caido, manual note, API response, signup flow, or child-agent output

## Authentication Resolution

For named accounts or colors, resolve auth in this order:

1. Read the account inventory for the selected alias/color and use the current
   non-secret references: `auth_seed_ref`, `credential_ref`,
   `auth_refresh_source`, `auth_refresh_hint`, `auth_session_mode`,
   `auth_check_url`, and `auth_host_filter`.
2. Honor `auth_session_mode` before inspecting or refreshing session material:
   `browser-bound` means do not copy a seed, cookie, bearer, or proxy-derived
   session. Lease the exact persistent browser profile and start the private
   Tailscale/SSH manual-login handoff. `unknown` also fails closed into that
   handoff; only `proxy-replayable` permits the explicitly recorded approved
   refresh source, while `hybrid` retains the existing safe fallback.
3. Try the current stored auth seed/session or secret-store reference in the
   agent lane when the recorded session mode permits it.
4. When no usable seed exists and the program record permits it, automatically
   refresh only the selected account from Ryushe's proxy. Never reset an
   existing seed simply because the resolver runs.
5. Use the resolver script instead of hand-rolling host/proxy decisions:
   ```bash
   python3 $HARNESS_ROOT/skills/account-management/scripts/auth_resolver.py resolve \
     --program {program} \
     --account blue \
     --json
   ```
   The resolver reads the proxy route table to decide whether this runtime can
   query Ryushe's proxy directly, must use one-shot Hoster SSH, or must fail
   closed.
6. If Ryushe's proxy cannot be reached, has no matching account evidence, or
   cannot refresh the selected account, try that exact account browser profile's
   existing session or browser-native recorded login.
7. If it still cannot authenticate, retain its exact browser lease as
   `awaiting-input`, give Ryushe the private Tailscale Serve handoff plus its
   SSH-loopback fallback, and pause automation. Do not substitute another
   account.

After a proxy-derived refresh, active testing must use the agent MITM lane unless the agent is executing locally on Abommie. Do not test through Ryushe's proxy just because the account evidence came from there.

## IDAWR second-account and lease handoff

For any cross-account test, first list the current non-secret color/lease state;
do not assume a remembered lane is still free:

```bash
python3 $HARNESS_ROOT/skills/chromium-test/scripts/browser_profile_lease.py \
  status {program} --testing-role idawr
```

The structured result includes every mapped `color_availability` row (`available`,
`locked`, or `unavailable`) and the current IDAWR pool. Select one explicit
available `idawr-*` alias/color, then acquire its profile; the helper never
auto-switches accounts. When login needs Ryushe, retain the lease as
`awaiting-input`, start the exact profile's private `chromium-handoff`, and give
Ryushe its Tailnet/Tailscale Serve URL plus scoped SSH-loopback fallback. Never
expose CDP or publish a public route. On terminal completion, release the same
lease with an honest profile-health disposition so the IDAWR account is unlocked
for other agents; a lockout/step-up requires `needs-refresh` rather than calling
the account available.

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
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-account {program} --alias primary --email ryushe+ai@example.com --user-id USER_ID --tier admin --credential-ref "bitwarden:item-name" --auth-seed-ref "auth-seed:/secure/path/primary.json" --auth-check-url "https://target.example/account" --auth-host-filter "target.example" --pwnfox-color blue --lifecycle active --browser-lease-enabled yes --organization-access owned-team:admin:enterprise --capability billing:invoices --capability shared-org:owned-team --destructible no
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-account {program} --alias idawr-pink --email ryushe+ai+pink@example.com --tier user --testing-role idawr --pwnfox-color pink --lifecycle active --browser-lease-enabled yes --destructible yes
python3 $HARNESS_ROOT/skills/account-management/scripts/auth_resolver.py resolve --program {program} --account blue
python3 $HARNESS_ROOT/skills/account-management/scripts/auth_resolver.py refresh-from-ryushe-proxy --program {program} --account blue --host-filter target.example
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-resource {program} --type design --id DESIGN_ID --name "profile test design" --owner primary --url https://target.example/design/DESIGN_ID --cleanup-needed yes
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py link-pwnfox {program} --color blue --account primary
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py link-login {program} --account primary --provider google --identity owned@example.com --source browser
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-integration {program} --account primary --provider github --integration-id installation-123 --external-account owned-test-org --capability repo:read --source browser
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py set-integration-profile {program} --account primary --source browser
```

## Routing

- Before `/idor`, `/access-control`, `/jwt-auth`, `/payment-testing`, `/pfp`,
  `/single-request-grabber`, or `/pwnfox` comparisons, load this skill if owned
  account/resource identity is unclear.
- After `/create-account`, browser setup, proxy mapping, linked-login/social
  account changes, integration connect/disconnect/reauthorization or visible
  capability changes, document creation, upload creation, order/checkout setup,
  or workspace creation, update the registry before handing work to child
  agents. A child that observes one of these changes must return the exact
  non-secret registry command or JSON patch in its handoff.
- When Ryushe says “integration profile” or asks to integrate onto a profile,
  use the active designated `integration-profile` account for that program.
  If none is active, first designate an existing owned account with
  `set-integration-profile`; never create, rename, or substitute a real email
  account without an explicit approved account record.
- Before any integration connect/create/reconnect/reauthorization, first read
  the inventory's existing provider records, then load `/bitwarden` and verify
  the selected account has an approved ready provider-specific `bitwarden:<item>`
  reference. Existing active owned provider-available accounts are preferred;
  the pool is limited to valid owned Bitwarden entries for that service type.
  An unknown or connected provider record is occupied, not silently reusable.
  If availability is not clear, stop before signup/connection creation, follow
  account-creation policy, and ask Ryushe for a new non-disposable email or
  credential decision. After a successful connection, immediately run
  `add-integration` for the exact account used. Its `external_account` must
  match the Bitwarden login identity—email when that login uses an email,
  otherwise its username—so the ledger identifies the exact provider account.
  Child handoffs must include that update command or patch.

## Stop Conditions

Stop and ask Ryushe before recording real secrets, non-owned private data,
personal account details outside the approved test identity, or destructive
cleanup assumptions that are not explicit.
