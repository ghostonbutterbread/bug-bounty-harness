# Auth-seed capture, liveness, and planning-time usability

Use this before assigning authenticated work to a worker that will replay a
stored auth seed. The goal is to route around dead or empty seeds from
inventory metadata, before setup effort or live target requests.

## What is recorded (all non-secret)

- **Seed file** (`credentials/auth_seeds/<alias>.json`, mode 0600): the
  resolver's writer adds `captured_at` (UTC ISO-8601) when it writes a seed.
  Older seeds without it are read as capture time unknown.
- **Inventory account record** `auth_seed_status`, written by
  `auth_resolver.py` when it refreshes a seed or runs the declared liveness
  check:
  - `captured_at`, `auth_material` (`present`/`absent`),
    `replayable_cookie_count`, `auth_header_names` (names only);
  - after a check: `last_verified_at`, `last_verified_result`
    (`live`/`expired`/`unknown`), `last_verified_reason` (for example
    `http-401`, `cached-response`, `html-document`), and
    `last_verified_check` (method plus origin/path; the query is dropped).
- **Optional declared TTL** `auth_session_ttl_hours` on the account, from the
  absolute expiry in `auth-contract.md`
  (`account_inventory.py add-account ... --auth-session-ttl-hours N`).

Verification is stored in the inventory, not written back into the secret seed,
so a liveness check can never overwrite a seed that was refreshed meanwhile.
Verification belongs to one capture: when the seed on disk has a different
`captured_at`, the recorded result no longer applies.

## Usability states

`auth_seed_usability` appears in `browser_profile_lease.py status/acquire`
account summaries, `auth_resolver.py resolve/refresh` output, `chromium_test.py`
account resolution, and as `seed=<state>(<reasons>)` in
`account_inventory.py show`:

| State | Meaning | Planner action |
| --- | --- | --- |
| `usable` | Verified `live` within the window (declared TTL, else 24h) | Assign |
| `unverified` | No applicable recent live check (includes old records) | Run `auth_resolver.py resolve` once before assigning |
| `stale` | Last check `expired`, or seed older than the declared TTL | Refresh first (approved source only) |
| `unusable` | No replayable auth material, or the seed file is missing/unreadable | Refresh or pick another fixture |
| `none` | No auth-seed reference (browser-bound or credential-only account) | Use the browser/credential path |

Old inventories and seeds never read as `usable`.

## Replayable auth material

A seed has material when it holds at least one cookie with a non-empty value,
or a header whose name looks like auth (`auth`, `token`, `session`, `cookie`,
`key`, `bearer`, `jwt`, `credential`; CSRF/XSRF tokens alone do not count).
A program whose auth rides in an unusual header must list it in
`auth_check.required_header_names`. The resolver skips the liveness request for
a seed without material, and a Ryushe-proxy refresh never replaces an existing
seed with one that has none.

## Choosing a liveness discriminator (`auth_check`)

The check must respond differently by auth state: a JSON API that returns 401,
or a structured auth error such as an "expired" envelope, when logged out.
Do not use the site root, a static file, or an SPA shell. A CDN cache hit
(`cf-cache-status: HIT`, `X-Cache: HIT`, `Age > 0`) never reached the origin
with our credentials, and an HTML document is typically 200 whether or not the
session is valid (including a login page reached through a redirect). The
resolver records those 2xx responses as `inconclusive`/`unknown`, not `live`,
and `add-account` warns when the URL is the site root or a static file. An
inconclusive check neither revives nor overwrites a recorded `live`/`expired`
result for the same capture; readiness then falls back to material plus the
recorded state, exactly as when no check URL is declared (so callers such as
`recon_ry.py --auth`, which pass their target as `--target-url`, keep working
while the seed stays visibly `unverified`). A 200
JSON body that carries an auth error is not parsed generically; choose an
endpoint whose status code changes, or record the envelope in
`auth-contract.md` for the worker.
