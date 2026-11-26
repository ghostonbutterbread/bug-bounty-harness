# Integration dossier: feat/scope-inventory

- Task: typed scope inventory and change history on every pull, a
  release-changed signal for apps and executables, offline backfill, and
  refresh-when-a-week-old for agents
- Worktree: `~/projects/bbh-feat-scope-inventory`
- Branch: `feat/scope-inventory`
- Base (origin/beta): `cfd1c9bd031a66a3425ad02958ea88bd0fe20072`
- Merge target: beta (Hermes merges after independent review)
- Companion: Bounty Board builder (separate repo) reads the three files

## Intent

Ryu, verbatim:

> we want to be able to see when scope and apps update scope and to be able to
> track the inscope etc items
> a) Track what the program lists in scope (apps, exes, source code) and show
> when that changes.
> b) Also notice new app or exe releases, so the binaries lane gets refreshed.

> [weekly re-pull] i like this but i dont think we really have the things in
> place to be able to do so since i believe that agents pull scope primiarily,
> so what we could od is instead have the agent update scope if the scope is a
> week old (if it starts to work on the prograom) instead of having the board
> do so

> then on the read these yourself, thats more program policy so you can just
> put the program policy there

> release changed is good enough for now (mobile apps and such) and ya build
> it out

BBH's part: write the inventory files on every pull, backfill them offline,
check release signals during real pulls, and let agents refresh stale scope
without blocking on a failed pull. The Board renders the unchanged
`program-policy.md` instead of a "read these yourself" list.

## What changed

Files: new `agents/scope_inventory.py`, `agents/scope_puller.py`,
`agents/url_ingest.py` (one flag), new `agents/test_scope_inventory.py`,
`skills/pullscope/SKILL.md`, new `skills/pullscope/references/scope-inventory.md`.

### 1. Inventory on every pull

`save_scope` writes the existing files exactly as before (`write_if_changed`
unchanged), then calls `scope_inventory.write_inventory(base, source="pull")`.
The inventory is built **from the saved files** (`assets.json`,
`out-of-scope.json`, `in-scope.txt`, `out-of-scope.txt`, `scope-review.json`),
so a pull and an offline rebuild share one normalizer. An inventory error
prints a warning and never fails a saved pull.

- `scope-items.json` and `scope-pull.json`: temp file in the same directory,
  fsync, `os.replace`. `scope-history.jsonl`: one `write` of one complete line
  in append mode, fsync.
- Normalizer (`iter_asset_records` + `normalize_record`) walks every saved
  shape: H1 groups of `targets` with `asset_type`, Bugcrowd groups of
  `targets` with `category`, Bugcrowd flat target lists, Intigriti
  `tier-N` groups, raw H1 nodes (`asset_identifier`, `eligible_for_submission`),
  hand-made dicts (`assets: [{type, identifier}]`, `target_groups`,
  `mobile`/`web`), and plain strings.
- Kind: a known platform type decides (`TYPE_KINDS`); web-ish types
  (`URL`, `website`, `api`, `WILDCARD`, `CIDR`) and untyped or `OTHER`
  records are classified from the value shape (`infer_from_value`): Play and
  App Store URLs, hosted-repo URLs (`source_code`), download URLs by file
  extension (`executable`), URL, CIDR, IP, wildcard, host,
  `<host> Web Apps`, and the `<words> - <rule>` export shape. Anything else is
  `other` keyed by the normalized name.
- `enforced`: an item's candidate forms (raw values, the puller's
  `routable_scope_entry` forms, reviewed grant/exclusion entries) are matched
  against the rule-shaped lines of `in-scope.txt` (in-scope items) or
  `out-of-scope.txt` (out-of-scope items). Lines with whitespace are prose the
  checker skips, so they never make an item enforced.
- A dir with no typed in-scope record falls back to (a) re-reading a saved
  `raw/intigriti-page.html` with the existing Intigriti parser, then (b) the
  rule lines themselves (`platform_type: null`).
- History: first inventory writes one `baseline` line listing every item.
  After that a line is appended only for added, removed, changed
  (`in_scope`, `tier`, `max_severity`, `eligible_for_bounty`, `name`) or
  `release_changed` entries.

### 2. Offline rebuild

`bbh agents/scope_puller.py --rebuild-inventory <program>` and
`--rebuild-inventory --all`. No network (the release check never runs on
`rebuild`), and only the three inventory files are written. `--all` skips
symlinked alias dirs and dot dirs and continues past a failing dir (exit 1 if
any failed). Rebuild timestamps: `first_seen`/`last_seen` keep previous values;
a new item uses the mtime of `assets.json` (else `in-scope.txt`) as its
observation time. `scope-pull.json` keeps its pull fields; a fresh one has
`pulled_at: null`.

### 3. Release-changed signal

Real pulls only, in-scope `ios_app`, `android_app`, `executable` items, one
request each, 15 s timeout, sequential:

| Kind | Method | Signal |
|---|---|---|
| `ios_app` numeric id / bundle id | `itunes_lookup` GET `itunes.apple.com/lookup?id=` / `?bundleId=` | `version currentVersionReleaseDate`; `version` recorded |
| `android_app` package id | `play_page` GET `play.google.com/store/apps/details?id=…&hl=en_US&gl=US` | `Updated on <date>` text |
| `android_app` `.apk`/`.aab` URL, `executable` http(s) URL | `download_head` HEAD (redirects keep HEAD) | `etag=…; last-modified=…; content-length=…` |

Failures (timeout, HTTP error, unparseable page) set `release.error` and keep
the last known `signal`, so the next successful check compares against it.
No checkable identifier: `method: null`, `error` = `no download URL` /
`no package id` / `no App Store id`. `--no-release-check` skips all requests
and carries the previous `release` unchanged. `url_ingest`'s fallback pull now
passes `--no-release-check`: it runs under a 90 s subprocess timeout and only
needs the scope files.

### 4. Refresh when a week old

`bbh agents/scope_puller.py <program> --if-older-than DAYS`:

- age = now − `scope-pull.json` `pulled_at`, else mtime of `assets.json` /
  `in-scope.txt`. Fresh: print `scope fresh (pulled N days ago)`, exit 0,
  **write nothing**.
- Stale and `last_failed_at` within 24 h: record `skipped_backoff`, print a
  one-line warning with the retry time, exit 0.
- Otherwise pull. Any exception, or the fetch returning nothing, records
  `failed`, `last_error`, `last_failed_at`, prints a one-line warning and
  exits 0. Scope files are untouched: `save_scope` builds every body before
  writing, and a parse failure raises before that.
- Missing scope dir: normal first pull. A failed first pull exits 1 and
  creates nothing (there is no saved scope to continue on, and an empty dir
  would turn `classify`'s `missing` into `empty`).

Plain pulls (no `--if-older-than`) also record `failed` when a scope dir
exists, and now exit 1 when the fetch returns nothing (it exited 0 before).

## Decisions

1. **`scope-pull.json` gains `last_failed_at`** (additive). The backoff keys on
   it, so a `skipped_backoff` record does not erase when the failure happened.
2. **`skipped_fresh` is never written**: fresh runs write nothing, as preferred.
3. **An asset listed both in and out of scope is `in_scope: false`**
   (exclusion wins, as in the checker). Bugcrowd lists out-of-scope targets in
   both `assets.json` and `out-of-scope.json`; they merge into one item.
4. **`items_hash`** is sha256 of the compact JSON of the sorted items limited to
   `key, kind, identifier, name, in_scope, tier, max_severity,
   eligible_for_bounty, enforced, platform_type, description` (no timestamps,
   no release), so it changes only when the listed scope changes.
5. **Baseline** is written when there is no readable `scope-items.json`, not
   when the history file is empty. Deleting `scope-items.json` produces a
   second baseline instead of a full removed/added diff.
6. **A rebuild-then-pull can log one spurious diff** where the saved files and
   a fresh platform response normalize differently (e.g. a hand-made
   `assets.json` replaced by a real pull). That is the real file change.
7. **Store URLs in Bugcrowd `uri` fields are already in `in-scope.txt`** (the
   puller adds every in-scope URI), so those app items show `enforced: true`.
   That is truthful: the checker would match the store URL.
8. **Play `Updated on` text** is the signal as-is (not hashed); it is short and
   readable on the Board. An `android_app` with a non-file URL (a landing page)
   gets `no package id` rather than a HEAD on a page whose ETag changes with
   every deploy.
9. **A scheme-only exclusion excludes the host item.** In-scope
   `https://a.x` plus out-of-scope `http://a.x` becomes one
   `web_host:a.x` with `in_scope: false`. That matches the checker, because
   `out-of-scope.txt` reduces an exclusion URL to its host.
10. **`executable` download URL** comes only from the item's identifier or `uri`,
   not from prose descriptions, which often link to docs pages.

## Read-only survey (shapes and counts only)

56 scope dirs copied (scope files only, no SQLite) to a scratch dir;
`--rebuild-inventory --all` ran on the copy: 56 inventories, 0 failures, 56
baseline lines, 8 empty inventories (dirs with no assets and no rule lines).

| Platform (dirs) | Assets shapes seen |
|---|---|
| hackerone (25) | 12 group/`targets` with `asset_type`; 6 hand-made dicts (`assets: [{type, identifier}]`, `target_groups`); 7 empty lists |
| bugcrowd (21) | 52 nested groups with `targets[]` + `category`; 84 flat target records with `group`/`tags`/`rewardRange` |
| intigriti (9) | 3 tiered `targets` lists; 5 empty lists with a saved rendered page (re-read: 64 app items); 1 hand-made `web`/`mobile`/`tiers` dict |
| yeswehack (1), unknown (2) | `scope_type`/`asset_value` records; rule lines only |

Kinds after the rebuild: `web_host` 765, `web_wildcard` 190, `web_url` 64,
`cidr` 69, `ip` 9, `android_app` 74, `ios_app` 75, `executable` 15,
`source_code` 11, `other` 74 (1,346 items). Items with no platform type: 28
(untyped records plus rule-line fallbacks), all classified from the value. In-scope web items not enforced: 28 (scheme-less
`host/path` records and URI forms that differ from the saved rule line).

## Tests

```bash
PYTHONPATH=$PWD .venv/bin/python -m pytest -q -p no:cacheprovider <files>
```

New: `agents/test_scope_inventory.py` (26 tests): per-platform normalization
(H1 through `save_scope`, Bugcrowd nested, Intigriti tiers and saved-page
re-read, untyped, hand-made and rule-line fallback), `enforced`, stable keys
and `first_seen`, history baseline/added/removed/changed/no-change/append-only,
release methods with mocked responses including timeout, HTTP 404, URLError,
bad payloads and `--no-release-check`, offline rebuild touching only the three
files (network guard armed), `--if-older-than` fresh/mtime fallback/failed pull
keeps files and exits 0/backoff/retry after 24 h/missing dir, success clears
failure state, atomic write on crash, inventory failure isolation.

New file after review: 30 tests. Results:

- Full run (19 files touching `scope_puller`/`scope_validator`/`scope_seed_files`/`url_ingest`,
  plus the new file, `tests/test_program_init.py`, `tests/test_skill_hygiene.py`,
  `tests/test_recon_ry_start_ports.py`) on d62194bc: 2052 passed, 12 failed, 27 subtests passed (24 min).
  The failures came from two test assumptions: `url_ingest` tests read the platform as the
  last argv item (fixed by putting `--no-release-check` before `--platform`), and two puller
  tests patch `save_scope` with a two-argument lambda (lambdas now accept `**_kw`).
- After the fixes: `test_scope_puller_seed_files`, `test_scope_inventory`, `test_url_ingest`,
  `test_scope_review_file`, `test_bugcrowd_scope_review_regressions`, `test_skill_hygiene`:
  153 passed, 26 subtests passed. `test_base_team_storage`, `test_recon_store`,
  `test_program_init`, `test_bbh_launcher`: 70 passed. `agents/test_portable_import_paths.py`
  run on its own (see `BUGFIXES.md`): 2 passed.

## Gaps

- No lock: two concurrent pulls of the same program could interleave history
  lines (each line stays whole). Agents rarely pull the same program at once.
- Release checks are sequential; a program with many apps adds up to 15 s per
  unreachable item.
- The Play page format can change; that shows up as `release.error`, not a
  crash. Region-restricted apps may return 404 from the US Play page.
- Intigriti, Bugcrowd and YesWeHack carry no `eligible_for_bounty` or
  `max_severity` per target, so those stay null.
- History records `tier` changes only where a tier can be read from the group
  name (`Tier 1`, `tier-2`).

## Review

### Builder-side review (fresh subagent, before hand-off)

Five findings, fixed in the review commit with regression tests:

1. A malformed hand-made `web` block (string or int instead of a list) made
   per-character junk items or crashed the rebuild. Now non-lists are ignored,
   and a single-program rebuild reports one line and exits 1 instead of
   printing a traceback.
2. Duplicate records (the same host in several Bugcrowd groups) merged in file
   order, so reordering `assets.json` logged a false tier/name change. Records
   are now sorted before merging (lowest tier label first).
3. `http://` exclusion vs `https://` grant: kept, see decision 9.
4. If the inventory write failed, `pulled_at` was never updated and every
   `--if-older-than` run pulled again. The except branch now records `ok`
   and `pulled_at`.
5. `scope-items.json` was replaced before the history append, so a failed
   append lost the change. History is appended first; a failure after it
   repeats a line on the next run rather than dropping one.

Minor: a non-ISO `first_seen`/`last_seen` in a hand-edited items file is
replaced.

Independent review: pending (Hermes).
