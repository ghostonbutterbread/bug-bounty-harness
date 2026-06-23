# Account Management Playbook

Use this to make owned-account and owned-object context reusable across manual
hunting, automated agents, IDOR/BOLA checks, PwnFox lane comparisons, and
cleanup.

## Storage

Canonical registry:

```text
$HARNESS_SHARED_BASE/{program}/credentials/account_inventory.json
```

Default base:

```text
/home/ryushe/Shared/bounty_recon/{program}/credentials/account_inventory.json
```

The registry is non-secret. Store Bitwarden item names or approved credential
references instead of credential values.

## Proxy Identity Config

Each registry carries this non-secret PwnFox lookup contract:

- `proxy_identity.pwnfox.header_name`: `X-PwnFox-Color`
- `proxy_identity.pwnfox.header_value_format`: lowercase color string
- `proxy_identity.pwnfox.caido_httpql_presence_filter`: `req.raw.cont:"X-PwnFox-Color"`
- `proxy_identity.pwnfox.caido_httpql_color_filter_template`: `req.raw.cont:"X-PwnFox-Color" AND req.raw.cont:"{color}"`

Agents should read this block before querying Caido. Do not invent alternate
spellings unless live traffic proves a second header exists.

## Minimum Account Fields

- `alias`: short stable handle such as `primary`, `secondary`, `blue`, `admin-test`
- `email` or `username`: only if approved and useful for agent handoff
- `user_id`: app-visible ID, UUID, GraphQL global ID, account ID, member ID, or profile ID
- `role`: user/admin/member/owner/free/paid/etc. when known
- `tenant_id` or workspace/team/org ID when relevant
- `credential_ref`: Bitwarden item name or approved pointer, never the secret
- `auth_seed_ref`: locked-down local auth seed pointer such as `auth-seed:/path/to/account.json`
- `auth_refresh_source`: approved fallback source such as `ryushe-proxy`, `manual`, or `secret-store`
- `auth_refresh_hint`: non-secret lookup hint such as `pwnfox:blue`
- `auth_check_url`: safe read-only account URL for auth validation, such as an account/profile page
- `auth_host_filter`: non-secret host substring to keep Ryushe-proxy lookup scoped, such as `canva.com`
- `pwnfox_color`: observed lane if mapped
- `destructible`: `yes`, `no`, or `unknown`
- `source`: where the value came from

## Minimum Resource Fields

- `type`: design, document, upload, workspace, team, order, invoice, profile, asset, etc.
- `id`: exact object identifier observed in URL/API/UI
- `name`: human-readable label if available
- `owner`: account alias from the registry
- `url`: full URL where the resource was observed or managed
- `pwnfox_color`: if observed through a colored profile
- `run_id` or `session_id`: if created during an agent run
- `cleanup_needed`: `yes`, `no`, or `unknown`
- `destructible`: `yes`, `no`, or `unknown`
- `source`: browser, Caido, API response, manual note, or script

## Workflow

1. Before testing, run `show` and identify the owned accounts/resources for the lane.
2. For named account auth, call the resolver instead of reimplementing host,
   proxy, and fallback logic:
   ```bash
   python3 $HARNESS_ROOT/skills/account-management/scripts/auth_resolver.py resolve \
     --program <program> \
     --account <alias-or-pwnfox-color> \
     --host-filter <target-host-or-domain>
   ```
3. The resolver reads the proxy route table and decides whether Ryushe-proxy
   lookup is direct on Hoster, one-shot SSH through Hoster from OpenClaw/Ghost,
   same-host localhost on Ryushe PC, or blocked.
4. For named account auth, the resolver tries the current stored
   `auth_seed_ref`, `credential_ref`, or approved secret-store reference first.
5. If stored auth fails and the account record allows `auth_refresh_source`,
   use that source only for the selected account. For `ryushe-proxy`, pull
   request shape or refresh the selected auth seed only; active testing still
   happens through the agent MITM lane.
6. If Ryushe's proxy is unreachable or has no matching usable evidence, load
   `/bitwarden` and use the recorded Bitwarden reference as fallback.
7. If an account exists but lacks a user ID or PwnFox color, record the missing field once observed.
8. When creating a document/design/upload/order/workspace, immediately add a resource record.
9. For cross-account tests, compare only records with clear ownership and destructible status.
10. If a child agent creates or observes a new ID, it must return a registry update command or JSON patch in its handoff.
11. After cleanup, update the resource with `cleanup_needed no` and a note.

## Agent Handoff Packet

When spawning an IDOR/access-control/JWT/PwnFox child agent, include:

- program
- registry path
- account aliases involved
- PwnFox color mapping if present
- exact PwnFox header/query config from `proxy_identity.pwnfox`
- resource IDs/types and owner aliases
- destructible/cleanup status
- one exact target flow or URL group
- stop condition

Do not include secrets. If the child needs authenticated traffic, route through
approved proxy/browser/session mechanisms instead of copying credentials.
