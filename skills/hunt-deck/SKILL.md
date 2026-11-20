---
name: hunt-deck
description: "Use HuntDeck to find and compare bounty programs."
---

# Hunt Deck

Prefer HuntDeck over BountyLens for discovering and comparing bug bounty
programs. Load `program-finder` for shortlist criteria and authoritative program
verification; this skill owns using and, when necessary, bringing up HuntDeck.
It is a discovery source, not permission to test or the canonical hunt store.

## Reach the existing instance

The existing Hoster instance is `https://hoster.taildb09a3.ts.net:9000`.
On Hoster itself it is `http://127.0.0.1:9000`; localhost on another machine is
not Hoster. `GET /healthz`, then `GET /api/v1/status`, establish availability
and platform check times. A healthy service can still have stale or missing
platform data; record freshness and unknowns. Inspect before doing anything
that changes service state. Hoster work follows `hoster-ssh` and its cleanup
sidecar. Hoster's verified project is `~/projects/huntdeck`, not BountyLens.

## Discover and compare

1. Use the Hunt board, Programs, Stats and Changes views, or the read-only API.
   Examples below use the tailnet URL; on Hoster use its loopback URL instead.
   Inspect the running instance's `/api/v1/openapi.json` for current filters:

   ```sh
   curl -fsS 'https://hoster.taildb09a3.ts.net:9000/api/v1/status'
   curl -fsS 'https://hoster.taildb09a3.ts.net:9000/api/v1/programs?visibility=public&bounty=1&top=3000&sort=quiet&limit=100&offset=0'
   curl -fsS 'https://hoster.taildb09a3.ts.net:9000/api/v1/programs?visibility=public&bounty=1&new=30d&sort=huntscore&limit=100&offset=0'
   ```

   `top` is a **minimum** top bounty in each program's own currency, not a
   maximum or dollar conversion. Apply the user's range and currency criteria
   separately; do not silently discard programs with unknown bounty values.
   List responses provide `total` and `programs`; `limit` and `offset` are
   request parameters. Paginate when completeness matters and state query
   coverage. Public shortlist searches must set `visibility=public` and avoid
   returning private program details in tool output. Private-program discovery
   requires explicit authorization and a private output destination. Filters and
   fresh-scope lists are leads, not an exhaustive paid-program directory.
   Consider other platforms/direct programs and use `bountylens` when HuntDeck
   is unavailable or adds useful coverage.
2. Open a promising row's `/api/v1/programs/{platform}/{handle}` and, when
   supported, `/api/v2/programs/{platform}/{handle}` for per-field provenance,
   timestamps and estimates. Changes can be queried at
   `/api/v1/changes?since=30d&program={platform}/{handle}`. Check score parts,
   activity, trend coverage, scope changes, rewards and requirements. HuntScore
   and quiet sorting suggest where to look, not proven low competition. Retain
   null as unknown and label estimates, sample duration, and `last_synced_at`.
   First-seen is not necessarily platform launch; first response or validation
   speed is not payout or remediation speed. Scores/currencies do not become
   comparable just because they have numbers.
3. Return candidates with canonical program links, timestamp and concise
   reasons, separating cache observations from confirmed facts. Verify current
   paid status, actual critical maximum, scope, exclusions, eligibility and
   rules at the authoritative platform/program page before a paid shortlist or
   target interaction. Use `program-finder`'s existing evidence and handoff
   rules; load `general-security-testing-policy`, `program-testing-policy` and
   `pullscope` after selection. No recon, target request or account creation is
   part of selecting a program.

Changes and disclosed report links can guide follow-up; retrieve originals under
`safe-fetch` before making report claims. Scope checks and Burp/ZAP/Caido exports
are conveniences, not independent authority for scope or exclusions. Local
MapStore, notes, evidence, findings and ledgers remain the hunt records.

## Recover or install when unavailable

The user wants agents able to bring up the service, preferring port 9000. Do so
only for a program-discovery need, respecting service ownership and private-data
boundaries; do not let availability work block all discovery. If recovery is
blocked, explain the issue and continue with other sources.

1. First check the actual host and project, the health endpoint, port 9000,
   existing Compose/container and any existing service owner. Hoster's project is
   `~/projects/huntdeck`; elsewhere inspect `~/projects` and existing compose
   ownership before choosing a directory. Never assume the BountyLens project is
   HuntDeck or replace its files. Follow `service-lifecycle-policy`; do not run
   a second owner or disrupt an existing one. An occupied port is not permission
   to stop its owner, rebind a service, or choose a public listener.
2. If the existing HuntDeck Compose container is merely stopped and its owner,
   project, data and configuration are verified, start the existing service from
   its project directory with `docker compose start huntdeck`. If the service is
   absent but the project and deployment configuration are verified, use
   `docker compose up -d huntdeck` there. Inspect the plan and existing config
   first: `up` can create or recreate a container. Do not run it against an
   active but unhealthy container, change its image, pull an update, wipe or
   reinitialize a volume, or change credentials just to recover it. Diagnose and
   ask for the appropriate decision instead.
3. If no existing project or workload is found and installation is appropriate,
   check Docker and Compose, then clone `https://github.com/mdpsec/huntdeck.git`
   into a new `~/projects/huntdeck` directory; never overwrite a pre-existing
   directory. Review upstream README, Compose and configuration before use.
   Configure `HUNTDECK_PUBLISH=127.0.0.1:9000` in the project's existing `.env`
   without overwriting other values; create an owner-only `.env` if absent.
   Compose's upstream default is 8080, so verify the effective mapping before
   `docker compose up -d huntdeck`. Use the existing image/build instructions;
   do not install system packages or configure platform credentials without a
   separate approved credential workflow. A clean first start may import the
   public seed and takes time. Never print `.env`, secrets, tokens or session
   data; use secret-aware credential handoff rather than asking for secrets in
   chat. Do not publish directly to the internet.
4. Verify the *actual* listener and `/healthz`, then `/api/v1/status` and
   `docker compose ps`. Confirm port 9000 is the intended workload, one owner
   exists and report platform freshness and whether credentials/private programs
   are unknown. A successful command or health check is not proof that platform
   credentials or polls succeeded. Reach remote hosts via their existing private
   network setup; changing Tailscale Serve or firewall exposure is a separate
   operator-approved action. If port 9000 is in use, preserve the owner and
   report the conflict rather than silently switching ports.

## Privacy and stop conditions

HuntDeck has no built-in login: anyone who can reach it may read private program
information or trigger changes. Preserve loopback/private-network exposure and
platform confidentiality. Do not post private program data to third-party
services or general chat without an appropriate disclosure decision. Do not
accept invitations, change settings, trigger polls, change tags or notifications,
or export private data externally as a side effect of discovery. Stop rather
than bypass access controls, overwrite existing projects/configuration or modify
an ambiguous service owner. If unavailable, report the limitation and continue
with BountyLens or current public program pages.

## JavaScript Lens

Not applicable before program selection. After the authoritative rules/scope
check, route actual source/runtime mapping to `js` and `live-map`.

## Verification

Confirm a real read-only status and filtered program query, verify freshness and
source links, and test recovery separately from normal use. Never report a
cached bounty, score or scope match as current program authorization.
