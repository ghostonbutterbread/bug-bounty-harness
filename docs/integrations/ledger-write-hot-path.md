# Ledger Write Hot Path — Integration Dossier

- **Branch:** `fix/ledger-write-hot-path`
- **Base / target:** `origin/beta` `0821e438` / `beta` (after independent review)
- **Trigger:** real-data failures on Hoster, 2026-11-24. The Bounty Board's
  writer calls (60 s timeout, writer disabled on timeout) failed on large lanes
  and on any lane with a legacy relative `report_dir`.

## Intent

1. A metadata write (`--edit-finding`, `--set-submission`, `--delete-finding`,
   `--repair-report-dirs`, `--help`) must not hash the lane's source tree.
2. One legacy record whose `report_dir` is relative (`reports/<FID>`) must not
   block every refreshing write in its lane. Unsafe values must still fail
   closed.

## Root causes

- `ManualHunter.__init__` called `get_snapshot_identity(source_root)` eagerly.
  For a non-git root, `_manifest_hash` reads and hashes every file. One example
  was a binaries/apk lane whose `extracted/` holds 57,705 files (573 MB); it
  took more than 120 s on Hoster. If `ManualHunter` passed no identity, Bounty
  Core's `VersionedFindingsLedger.__init__` would compute its own instead.
- The root that gets hashed is the lane's shared-brain index `target_root`, or
  `--source-root`. With neither, it is the **process cwd**. `bbh` does not
  change directory, so for the Board the cwd is the Board's own working
  directory. A git checkout there is cheap (`git rev-parse HEAD`). Real indexes
  under `~/Shared` point at `input/app_asar`, an offline JS campaign
  `offline_target`, and in one exe lane the **lane root itself**.
- Bounty Core's `_packet_dir` accepts only an absolute, exact-FID packet
  directly inside `reports_root`. `patch_finding_by_fid(refresh=True)`,
  `import_finding` and the delete's navigation refresh all preflight **every**
  finding, so one relative `report_dir` failed the whole lane. On `~/Shared`
  (read-only count): 38 ledgers and 357 findings. One finding in one lane has a
  relative `report_dir` (`reports/<FID>`) and a relative `evidence_path`.

## Contract

### Lazy snapshot identity

- `ManualHunter.snapshot_identity` / `.snapshot_id` are properties, computed on
  first use. `ManualHunter.version_label` is set directly; it equals what the
  identity reports (explicit `--version` or `SNAPSHOT_VERSION`).
- `create_team_ledger(..., snapshot_loader=callable)` (and `_from_storage`)
  builds a `TombstoneAwareFindingsLedger` with a deferred identity. Bounty
  Core's constructor gets a placeholder, so it does not hash. The loader runs
  once, **before** Bounty Core takes `ledger.lock`, in `check`,
  `import_finding`, `reserve_batch` (when something is not tombstoned) and
  `update`. These are the operations that stamp a snapshot or sighting.
  `ledger.snapshot_loaded` reports whether it ran. Callers that pass
  `snapshot_identity` keep the old behaviour.
- `--set-submission` reads the finding through `read_team_findings` (no
  snapshot ordering) instead of `ledger.list_all()`.
- Identity format, fields and **values are unchanged**. Existing ledgers,
  coverage marks and sighting comparisons stay valid.

### Manifest cache (non-git roots)

- `get_snapshot_identity(root, version_label, *, manifest_cache_dir=None)`. With
  a cache dir, `cached_manifest_hash` does one stat-only walk and builds a
  fingerprint: sha256 over every `(relpath, size, mtime_ns)`, plus file count,
  total size and max mtime. It reads and hashes file contents only when the
  fingerprint differs from the cached one. The result is byte-identical to the
  uncached `_manifest_hash`; tests and the benchmark check this.
- `ManualHunter` (ingest, `--hunt`, hunt context) uses
  `default_manifest_cache_dir()` = `${XDG_CACHE_HOME:-~/.cache}/bbh/snapshot-manifest/<sha256(root)>.json`.
  The cache is written atomically. A corrupt cache, a foreign root or schema, or
  an unwritable directory falls back to a recompute.

### Legacy packet pointers

- `agents/ledger_report_dirs.py` owns one rule set:
  - **`report_dir`.** It must be relative with no `..`, `~` or NUL. It is
    resolved against the lane root (`reports/<FID…>`), then against
    `reports_root` (`<FID…>`). It is accepted only when Bounty Core's own
    `_packet_dir` accepts the absolute result unchanged. An absolute path that
    is not in normal form (`//`, `/./`, trailing `/`, no `..`) is accepted on
    the same condition.
  - **Relative `report_path`/`evidence_path`.** These are accepted when the
    result stays lexically and resolved inside `reports_root` and outside
    `reports/raw`.
  - **Everything else** is reported as *manual review* and never rewritten.
- **Hot path.** BBH's `agents.ledger.patch_finding_by_fid` (used by
  `--edit-finding` and, through `update_team_finding`, `--set-submission`) and
  `TombstoneAwareFindingsLedger.import_finding` (`--from-file`/`--add`/watch)
  first call `normalize_lane_packet_pointers`. It holds `ledger.lock`
  exclusively and uses Bounty Core's atomic writer. It writes only when
  something changes and prints
  `[ledger] normalized N legacy packet pointer(s) …` on stderr. The delete path
  normalizes the remaining findings in memory before its commit.
- **Repair command.** No `ManualHunter` constructor, no hashing, no storage
  creation:

  ```text
  bbh agents/manual_hunter.py <program> --family F --lane L [--root ROOT] --repair-report-dirs [--dry-run|--apply]
  ```

  The default is a dry run, which writes nothing. Output lines:

  - `Would repair: FID key: stored -> canonical (reason)` (`Repaired:` with `--apply`)
  - `Manual review: FID key: stored (reason)`
  - `Summary: N repairable, M need manual review; nothing written|ledger rewritten`

  | Exit | Meaning |
  |---|---|
  | 0 | No issues, or all issues repaired with `--apply`. |
  | 2 | Issues remain: a dry run with issues, or manual-review items. |
  | 1 | Refused: missing lane ledger or malformed ledger. Nothing is written. |

  The scan and the rewrite run in one exclusive `ledger.lock` section. A
  malformed ledger is refused (`_assert_ledger_well_formed`), never rewritten.
  `--dry-run`/`--apply` without `--repair-report-dirs` is a usage error.

## Decisions

- **Cached manifest, not an input-artifact sha256.** Switching a binaries lane
  to the APK/EXE sha256 would change every future `snapshot_id`. Existing
  findings, coverage marks and sightings stamped with the manifest hash would
  then compare as a different snapshot. The cache keeps the values identical.
  It also needs no rule for which input artifact counts.
- **Host-local cache instead of a lane-local cache.** The cache key is the
  resolved root, so entries are still per lane and per root. A cache inside the
  lane would break when the hashed root *is* the lane (one real exe index): each
  cache write changes the tree it fingerprints, so the cache would never hit and
  the snapshot would drift. A lane-local cache would also churn through
  Syncthing for host-specific data.
- **Fingerprint uses per-file mtime_ns.** This catches edits, renames and
  additions that a (count, total size, max mtime) key misses, at the same
  stat-walk cost. Known limit: an edit that keeps both size and mtime is not
  detected (the same trade-off as make/rsync defaults).
- **The identity resolves outside the lock.** The deferred identity is forced
  before Bounty Core's locked section, so a cache-miss hash never blocks other
  ledger writers. As a result a duplicate ingest also resolves it; that path
  stays cached.
- **Normalization is persisted, not in-memory.** Bounty Core reads `ledger.json`
  itself under its lock, so the canonical value must be written before the
  call. The rewrite produces exactly what `--repair-report-dirs --apply` would.
- **Private Bounty Core imports.** `_packet_dir`, `_locked_payload` and
  `_write_json_atomic` are imported at the requirements.txt pin, with the same
  rationale as `ledger_tombstones.py`. Using `_packet_dir` keeps BBH's check
  identical to Bounty Core's guard.

## Evidence

The benchmark ran on a synthetic lane under TMPDIR: 50,000 files, 588 MB,
binaries/apk, `--root` explicit, shared-brain index → `extracted/`. Both trees
ran with direct Python and the same interpreter and Bounty Core pin. The page
cache was warm and the host load average was about 23, so the timings are noisy.

| Command (Board argument order) | base `0821e438` | branch |
|---|---|---|
| `--edit-finding D01 --patch-file P` | 3.55 / 3.90 / 3.27 s | 0.14 / 0.19 / 0.19 s |
| `--set-submission D01` | 3.45 / 3.73 / 4.16 s | 0.28 / 0.29 / 0.24 s |
| `--from-file` (new finding) | 3.53 / 3.60 s | cold cache 3.81 s; warm 1.22 / 1.50 s; after a content change 3.52 s; warm again 1.43 s |
| `--repair-report-dirs` | n/a | 0.16 s |

Under `cProfile`, a branch `--edit-finding` spends 0.22 s in total, with no
`rglob` or hashing. `first_snapshot` values matched between base, the branch's
cold and warm cache, and the uncached `_manifest_hash` after a change. On Hoster
the base hash took more than 120 s for a similar tree. The branch's metadata
paths do no hashing, so they no longer scale with tree size.

Tests: `agents/test_ledger_write_hot_path.py` (18 tests). Two mutants were
killed: disabling the hot-path normalization fails the relative-edit test, and
disabling the delete normalization fails the delete test.

## Gaps

- The first `--from-file` on a large non-git root still pays one full content
  hash. Every write to a lane whose index `target_root` is the lane root also
  pays it, because the tree changes on each write; that lane's `snapshot_id`
  also changes on every write, which was already true. Point such indexes at
  the input or extracted tree.
- Other identity callers still compute uncached identities: `base_team_core`,
  `zero_day_team`, `apk_team`, `apk_deep_dive`, `dynamic_agent_builder`,
  `me_ledger`, and `sync_reports` via `--hunt`. They could opt into
  `manifest_cache_dir` in a follow-up.
- Absolute `report_dir` values from another host or root are listed as manual
  review, not rewritten.
- The proper upstream home for the pointer normalization is Bounty Core's
  migration (`migrate_legacy_finding`).
