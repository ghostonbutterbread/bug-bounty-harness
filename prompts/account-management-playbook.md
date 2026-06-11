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
2. If an account exists but lacks a user ID or PwnFox color, record the missing field once observed.
3. When creating a document/design/upload/order/workspace, immediately add a resource record.
4. For cross-account tests, compare only records with clear ownership and destructible status.
5. If a child agent creates or observes a new ID, it must return a registry update command or JSON patch in its handoff.
6. After cleanup, update the resource with `cleanup_needed no` and a note.

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
