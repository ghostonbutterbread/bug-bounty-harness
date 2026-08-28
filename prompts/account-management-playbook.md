# Account Management Playbook

Use this to make owned-account and owned-object context reusable across manual
hunting, automated agents, IDOR/BOLA checks, PwnFox lane comparisons, and
cleanup.

## Storage

Canonical registry:

```text
$HARNESS_SHARED_BASE/{normalized-program}/credentials/account_inventory.json
```

Default base:

```text
/home/ryushe/Shared/web_bounty/{normalized-program}/credentials/account_inventory.json
```

The registry is non-secret. Store Bitwarden item names or approved credential
references instead of credential values. `normalized-program` is the selected
testing program lowercased with separators converted to `-`; it is never a
generic account inventory or a browser-lane path.

## Integration Profile

Each program may designate one existing owned account as its central
`integration-profile`. It is an account-manager label, not a new email address,
and it does not rename or change the designated account's credentials. Use it
for owned social/service connections (for example Reddit, Discord, or GitHub)
when an agent is explicitly asked to integrate something. The profile stays
per-program so its integrations and access remain auditable and balanced.

Before connecting an integration, set it from an existing owned account:

```bash
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py \
  set-integration-profile <program> --account <owned-active-alias> --source browser
```

Then use `--account integration-profile` with `link-login`, `add-integration`,
or the auth resolver. Both the designation and its designated account lifecycle
must be `active`; otherwise agents fail closed rather than selecting a different
account. `integration-profile` is reserved and cannot be an ordinary account
alias. Record its linked identities,
integration connection status, and visible non-secret capabilities immediately.
Never put its password, OAuth authorization code, token, cookie, or other
credential material in the ledger.

### Mandatory integration-account selection gate

Before an agent starts, creates, reconnects, or reauthorizes an integration for
service `<provider>`, it must complete this sequence:

1. Read the program's account inventory and identify the active
   `integration-profile` plus every account whose non-secret `integrations`
   records name `<provider>`. Treat an account as occupied for that provider
   when its record is `connected` or its status is unknown; do not guess that a
   missing record is free.
2. Load `/bitwarden`, run its required version/status preflight, and check the
   approved Bitwarden metadata for **that provider type** (for example, Reddit
   items before a Reddit integration). Count only active owned accounts with a
   valid provider-specific `bitwarden:<item>` reference; never print or copy
   passwords, tokens, private notes, or full item contents.
3. Prefer an existing active, Bitwarden-ready, provider-available integration
   account. The number of accounts usable for a provider is bounded by valid
   owned Bitwarden entries for that provider type—not by an agent's assumption
   that it can make another account.
4. If no candidate is clearly available, stop before signup or connection
   creation. Do not create another integration account merely because the
   ledger is incomplete. First record the specific missing availability evidence
   and follow the account-creation/ownership policy; ask Ryushe when creation
   would burn a non-disposable account or needs a new email/credential.
5. Immediately after a successful connection, write an `add-integration`
   record for the exact owned account used. Set `external_account` to the
   Bitwarden login identity for the provider: use the stored email address when
   the Bitwarden username is an email, otherwise use that stored username. This
   makes the ledger match the provider credential and shows exactly which Reddit,
   Discord, or other integration account is occupied. Also record provider,
   non-secret installation/workspace/connection ID, status, visible capability
   labels, and evidence source. A child handoff is incomplete until it includes
   that exact command or JSON patch.

This check is required even when the agent was asked to “integrate onto this
profile.” The phrase selects the profile; it does not skip availability or
Bitwarden readiness checks.

For example, if the provider is Reddit and Bitwarden has several valid owned
Reddit entries, that is the maximum candidate pool. Once an agent uses one, it
records the precise Bitwarden username/email in `external_account`, so later
agents can see which Reddit identity is already integrated with which owned
account.

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
- `primary_idor_accounts`: program-level ordered aliases for ordinary owned
  accounts agents should check first when they need a second identity for
  IDOR/BOLA. This does not change an account's role or email.
- `tenant_id` or workspace/team/org ID when relevant
- `credential_ref`: Bitwarden item name or approved pointer, never the secret
- `auth_seed_ref`: locked-down local auth seed pointer such as `auth-seed:/path/to/account.json`
- `auth_refresh_source`: approved fallback source such as `ryushe-proxy`, `manual`, or `secret-store`
- `auth_refresh_hint`: non-secret lookup hint such as `pwnfox:blue`
- `auth_session_mode`: program default or account override: `browser-bound`, `proxy-replayable`, `hybrid`, or `unknown`
- `auth_check_url`: safe read-only account URL for auth validation, such as an account/profile page
- `auth_host_filter`: non-secret host substring to keep Ryushe-proxy lookup scoped, such as `canva.com`
- `pwnfox_color`: observed lane if mapped
- `linked_logins`: linked non-secret sign-in identities. Each record has provider,
  approved provider identity/handle, link status, and evidence source. Record
  Google SSO and linked social identities here; never store OAuth authorization
  codes, access/refresh tokens, cookies, or provider credentials.
- `integrations`: connected non-secret integration records. Each record has
  provider, installation/workspace/connection identifier, approved external
  account handle or ID when known, connection status, non-secret capability
  labels, and evidence source. This is the ledger for which owned account has
  which connected services.
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
   For a cross-account test, also run the profile-host lease status command and
   include its current `color_availability` rows in the child handoff:
   ```bash
   python3 $HARNESS_ROOT/skills/chromium-test/scripts/browser_profile_lease.py \
     status <program> --idor
   ```
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
5. Read `auth_session_mode` before using any stored seed or proxy refresh. For
   `browser-bound` or `unknown`, do not copy session material or query Ryushe's
   proxy; start the exact-profile private browser handoff immediately.
6. If stored auth fails and the account record allows `auth_refresh_source`,
   use that source only for the selected account. For `ryushe-proxy`, pull
   request shape or refresh the selected auth seed only; active testing still
   happens through the agent MITM lane.
7. If Ryushe's proxy is unreachable or has no matching usable evidence, load
   `/bitwarden` and use the recorded Bitwarden reference as fallback.
8. If the selected owned account still has no usable session, do not change
   identity or return only a generic blocker. Verify the exact browser-profile
   lease, launch/reuse a task-owned isolated Hoster browser, and route Ryushe to
   its loopback-only manual handoff through `/chromium-handoff` + Tailscale
   Serve. Give the tailnet URL plus the scoped SSH-loopback fallback, retain the
   lease as `awaiting-input`, pause automation, then re-run the safe auth check
   after login. Do not expose CDP, use Funnel, or copy credentials into a child
   prompt. This Tailnet/Tailscale Serve URL and the scoped SSH-loopback fallback
   are mandatory in every `awaiting-input` login handoff.
9. If an account exists but lacks a user ID or PwnFox color, record the missing field once observed.
10. When an owned account links, unlinks, or changes a login method (Google SSO,
    social login, etc.), immediately run `link-login` so the account ledger
    stays current.
11. Before an integration is connected, disconnected, reauthorized, or its
    visible capability changes, complete the mandatory integration-account
    selection gate above. Immediately afterward, run `add-integration` with
    the observed non-secret status/capability data.
12. When creating a document/design/upload/order/workspace, immediately add a resource record.
13. For cross-account tests, compare only records with clear ownership and destructible status. Query `status <program> --idor` immediately before leasing: choose an available primary IDOR account first, or an explicit listed fallback if they are busy. Never borrow a locked color.
14. If a child agent creates or observes a new ID, login link, or integration,
    it must return the corresponding registry update command or JSON patch in
    its handoff.
15. After cleanup, update the resource with `cleanup_needed no` and a note. Release the exact browser-profile lease immediately with `completed`/`cancelled` and its honest profile health so the account is unlocked for another IDOR agent; preserve `needs-refresh` after a lockout or auth step-up.
    A `needs-refresh`/`needs-cleanup` profile stays unavailable for ordinary test
    work. Use an explicit `acquire ... --recover-profile` lease only to repair
    and revalidate that exact profile, then release it as `healthy` before it
    returns to the pool.

## Linked Login and Integration Commands

```bash
python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py link-login <program> \
  --account primary --provider google --identity ryushe+primary@example.com --source browser

python3 $HARNESS_ROOT/skills/account-management/scripts/account_inventory.py add-integration <program> \
  --account primary --provider github --integration-id installation-123 \
  --external-account ghost-test-org --capability repo:read --source browser
```

These commands are upserts. Use `--status unlinked` or `--status disconnected`
to retain a useful non-secret history record when a relationship is removed.

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
