# Scope inventory files

`bbh agents/scope_puller.py` writes three files beside the saved scope in
`~/Shared/scopes/<program>/`. Only the puller writes them; the Bounty Board and
agents only read. Timestamps are ISO 8601 UTC with `Z`. Readers ignore unknown
keys. Integration detail: `docs/integrations/scope-inventory.md`.

## `scope-items.json` — current typed inventory

One item per listed asset, sorted by `key`:

| Field | Meaning |
|---|---|
| `key` | `<kind>:<identifier>`, stable across pulls |
| `kind` | `web_host`, `web_wildcard`, `web_url`, `ip`, `cidr`, `android_app`, `ios_app`, `executable`, `source_code`, `cloud`, `other` |
| `identifier` | lowercase host, wildcard, URL, CIDR, package id, App Store id; for `other` the normalized name |
| `in_scope` | false for out-of-scope records; an asset listed both ways is out |
| `tier`, `max_severity`, `eligible_for_bounty` | from the platform, else null |
| `enforced` | true when the item produced a rule line in `in-scope.txt` / `out-of-scope.txt` the checker enforces |
| `platform_type` | raw platform type or category (`GOOGLE_PLAY_APP_ID`, `ios`, `website`), null when untyped |
| `first_seen` / `last_seen` | first pull that listed it (kept across pulls) / last pull that listed it |
| `release` | in-scope `android_app` / `ios_app` / `executable` only, see below |

`enforced: false` means the scope checker does not host-check the item: apps,
executables, prose such as `3rd party services`, and records the parser could not
turn into a strict rule. Read `program-policy.md` for those.

## `release` — release-changed signal

Checked only during a real pull, one request per in-scope item, 15 s timeout:

- `ios_app`: `https://itunes.apple.com/lookup?id=<id>` (or `bundleId=`); signal
  `version currentVersionReleaseDate`, `version` recorded.
- `android_app`: the public Play page; signal is the `Updated on <date>` text.
  An `.apk` download URL uses the HEAD method instead.
- `executable` with an http(s) URL: HEAD; signal from ETag / Last-Modified / Content-Length.

`changed_at` and `previous_signal` are set when the signal differs from the last
one. Values from the store or server are stripped of control characters and
capped (`signal` 200, `version` 64 characters). A failed check sets `error` and
keeps the last known `signal`. No checkable
identifier: `method: null` and `error` says why (`no download URL`,
`no package id`, `no App Store id`). A changed signal means "new build to look
at" for the binaries lane, not a confirmed version bump.

## `scope-history.jsonl` — change log

One line per pull or rebuild that changed something: `added`, `removed`,
`changed` (`in_scope`, `tier`, `max_severity`, `eligible_for_bounty`, `name`),
`release_changed`. The first inventory (no history yet) writes one `baseline` line
listing every item. If `scope-items.json` is lost while history exists, the next
run appends one `source: "rebuild"` line with `resync: true` (diffed against the
replayed history) instead of a second baseline. Tail the last lines; never rewrite.

## `scope-pull.json` — last pull state

`pulled_at` (last successful pull, null after a rebuild only),
`last_attempt_at`, `last_attempt_status` (`ok`, `failed`, `skipped_backoff`),
`last_error`, `last_failed_at`, `items`, `items_hash`.
