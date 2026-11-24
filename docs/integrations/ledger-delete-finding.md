# Ledger Delete Finding — Integration Dossier

- **Branch:** `feat/ledger-delete-finding`
- **Base / target:** `origin/beta` `3f72ed81` / `beta` (after independent review)
- **Request:** Ryushe wants archived findings to be deletable: archive first, then
  delete from the archive. The same path cleans up schema-placeholder findings.

## Intent

Archiving (`--edit-finding FID` with `{"status":"archive"}`) stays the reversible
first step. `--delete-finding` is the second, deliberate step. It removes the
record from the lane ledger, but it leaves an auditable, restorable tombstone,
and the deleted finding cannot quietly come back through later imports.

## CLI contract

```text
bbh agents/manual_hunter.py <program> --family F --lane L [--root ROOT] --delete-finding FID [--actor LABEL]
bbh agents/manual_hunter.py <program> --family F --lane L [--root ROOT] --restore-finding FID [--actor LABEL]
```

Both are mutually exclusive mode flags listed in `--help`, so the Board can
detect them there.

| Exit | Meaning |
|---|---|
| 0 | deleted (or restored) |
| 1 | refused; nothing written. Message on stderr as `[manual_hunter] …` |
| 3 | deleted and committed, but the navigation/index refresh failed (`Warning:` on stderr) |
| 2 | argparse usage error |

A delete is refused when:

- the FID is unknown;
- the status is not `archive` (top-level `status`, lower-cased and stripped;
  `current.status` is used only when there is no top-level status);
- an import is pending on the finding;
- the ledger is malformed or not a regular file;
- the FID is the **highest FID of its prefix** (see Decisions).

Output lines on success:

```text
Finding deleted: D07
Tombstone: <lane>/ledgers/deleted-findings.jsonl
Retired: <original path> -> <lane>/ledgers/_deleted/D07/<YYYYMMDDTHHMMSSZ>/<lane-relative path>
Kept (<reason>): <path>
```

`Kept` reasons:

- `not BBH-generated`
- `generated report edited (checksum mismatch)`
- `evidence edited after creation`
- `symlink (not followed)`
- `outside lane or behind a symlink`
- `outside the lane reports root`
- `report_path not owned by this FID` / `finalized_report_path not owned by this FID`
- `directory with non-generated content`
- `packet pointer rejected: …`

Restore prints `Finding restored: FID` and one `Restored file: <path>` line for
each file it moves back. It exits 3 if the restore committed but the refresh
failed. If the ledger write or the `restored` event append fails, it rolls back:
the ledger is rewritten without the record and files return to the retired area.

### Tombstone (`ledgers/deleted-findings.jsonl`, mode 0600, append-only)

```json
{"schema":"bbh-deleted-finding/1","event":"deleted","fid":"D07",
 "deleted_at":"2026-11-24T19:00:00Z","deleted_by":"<--actor or manual_hunter>",
 "ledger_path":"<abs ledger.json>","program":"…","family":"…","lane":"…",
 "identity_key":[file,line,class_name,type],
 "record":{…the full removed ledger record…},
 "artifacts":{"retired":[{"from":"…","to":"…"}],"kept":[{"path":"…","reason":"…"}]}}
```

Restore appends `{"event":"restored","fid":…,"restored_at":…,"restored_by":…,"restored_files":[…]}`.
If the ledger write fails after the tombstone append, the delete appends
`{"event":"delete_aborted"}`. The **latest** event for a FID decides whether
that FID is tombstoned.

## Decisions

- **Owner/writer.** The operation lives in `agents/ledger_tombstones.py`. It
  reuses Bounty Core's `_locked_payload` (`ledgers/ledger.lock` flock),
  `_write_json_atomic`, and payload migration, which is the same critical section
  `patch_finding_by_fid` uses. It does not add a parallel writer. Those helpers
  are private upstream; the natural long-term home is a Bounty Core
  `delete_finding_by_fid`. That is not done here because Bounty Core is a
  separately pinned repository.
- **Single critical section.** Under one exclusive lock, the delete runs: validate the raw file →
  locate → status check → classify artifacts → move generated artifacts →
  append and fsync the tombstone → atomic ledger write → refresh `indexes/`
  and report navigation → write the ledger again, because the evidence-only refresh may fill
  packet pointers. If the tombstone or ledger write fails, the moves are undone.
- **Fail closed.** Bounty Core reads an unparseable ledger as empty and writes
  that back. Delete and restore parse the raw file under the lock first and
  raise before anything is written. The pre-existing writers still have this
  defect; it is recorded in `BUGFIXES.md`.
- **Artifacts are retired (moved), not unlinked.** They go to
  `ledgers/_deleted/<FID>/<stamp>/`, with each file's lane-relative path preserved.
  - Generated reports are not always byte-reproducible from the final record.
    A record edited after generation still has an intact checksum but renders
    differently. Moving them keeps the delete fully recoverable, and
    `--restore-finding` puts them back.
  - The retired area is under `ledgers/`, not `reports/`, because markdown
    report scanners (`sync_reports`, `report_checker`) walk `reports/` and could
    re-import a retired file.
  - Retired files: a `bounty-core-finding-report` whose `generated-checksum`
    matches (REPORT/FINALIZED or a legacy `reports/findings/<bucket>/FID - *.md`),
    and an `EVIDENCE.md` that is byte-identical to Bounty Core's create-only
    template for this record. The template is rendered in scratch storage with
    the real `ensure_finding_evidence_packet`, not a copied template.
  - Everything else stays in place and is listed. Symlinks are never followed.
    Paths outside the lane, or behind a symlinked component, are never touched.
  - Afterwards, an empty `_meta/` and an empty packet directory are removed.
- **Tombstone log fails closed.** A symlinked log, a non-file log, or any
  unreadable non-empty line raises `CorruptTombstoneLogError` from the guard and
  from delete. That blocks imports and team reservations in the lane until the
  log is repaired, rather than silently disabling the guard. A delete also
  checks the log before appending to it.
- **Retire paths never traverse symlinks.** Each destination directory component
  under the lane is created one at a time and refused if it is a symlink, which
  covers a symlinked `ledgers/_deleted`. Restore requires the retired file to
  have no symlinked component.
- **Report pointers must belong to the FID.** A `report_path` or
  `finalized_report_path` outside Bounty Core's per-FID candidate set
  (`_candidate_paths_for_fid`) is never moved. It is kept and listed.
- **FID reuse.** Bounty Core's `_next_fid` allocates `max(suffix)+1` from the
  findings list alone. So the delete refuses the highest FID of its prefix,
  which keeps every deleted FID below the allocation high-water mark. A
  test covers this: after a delete, the next new finding gets `D04`, not the
  deleted `D02`. Lifting the restriction needs Bounty Core to honor a
  persisted high-water mark (see Gaps).

## Resurrection paths and handling

| Path | Match | Handling |
|---|---|---|
| `manual_hunter --from-file/--add/--interactive/--watch` → `import_finding` | key (file, line, class, type) | Wrapper skips it. The CLI prints `Skipped: FID was deleted…` and exits 1, and never links a duplicate comment to a deleted FID. |
| `sync_reports` → `import_finding` (a leftover markdown `**FID:**` brings back the old FID) | FID or key | Wrapper skips it; the summary reports `Skipped: N deleted findings`, not "already exists". |
| `report_checker` / `base_team` promotion / `apk_deep_dive` / `zero_day_team` → `update_team_finding` fallback `ledger_add` (patch misses a deleted FID) | FID or key | Guarded before `ledger_add`. Returns `{"tombstoned": true}` and logs `[ledger] Skipped tombstoned finding …`. |
| Team sighting/reservation: `base_team.reserve_findings`, `apk_compat`, `zero_day_team`, `apk_deep_dive` → `ledger.check` | key | `TombstoneAwareFindingsLedger.check` (returned by `create_team_ledger`) reports a duplicate with `tombstoned=True`. |
| `reserve_batch`, `VersionedFindingsLedger.update` | key / FID | Guarded in the same wrapper (batch keeps result order). |
| `me_ledger.py add` → `ledger_add` | key | Refused with the skip message, exit 1. |
| `bounty_core.add_finding` / `ledger_add` called directly from outside BBH | identity / key | **Not guarded** (no BBH callers; needs Bounty Core). |
| `migrate_ledger_payload` FID assignment for FID-less rows | n/a | Not an insert; no change. |

All guards use the latest-event tombstone set and Bounty Core's `_finding_key_for`.
When a candidate has no line and no type/title, the guard also matches on
(file, class), the same way Bounty Core's `import_finding`, `reserve_batch`, and
`ledger_check` match.
A tombstoned identity is therefore blocked exactly where Bounty Core would
already have deduplicated it against the live finding. `--restore-finding` is
the explicit override.

## Evidence

The interpreter is the shared BBH venv plus Bounty Core source at the
`requirements.txt` pin `9db8b23d`, via `PYTHONPATH`. The worktree has no `.venv`,
and offline install was impossible because a dependency was not in the uv cache.
`HOME` and `TMPDIR` pointed at scratch storage for every run.

- New: `tests/test_ledger_delete_finding.py` — **23 passed**.
- Relevant existing suites, plus the new file and the skill gates, ran in one
  command — **368 passed, 86 subtests passed**. Suites included:
  - manual_hunter ×3, me_ledger, ledger_v2 ×2;
  - base_team ledger/review/runtime/storage;
  - sync_reports ×2, report_checker ×2;
  - finding submission/visibility/report;
  - apk_deep_dive, zero_day_team, apk_team;
  - ledger skill visibility, skill hygiene, skill command lane safety, bbh launcher.
- `py_compile` on touched modules and `git diff --check`: clean.
- An independent review reported 4 important and 5 minor issues, 5 of them
  reproduced. All were fixed with regression tests, except the guard race window
  and the stale-tombstone-after-crash case (see Gaps). Non-dict ledger rows are
  already dropped by Bounty Core's read-time migration, so that point needs no change.
- `tests/skill_size_budget.json`: the `manual-hunter` budget goes from 136 to 140,
  for a 4-line pointer section. The full contract lives here.
- One existing assertion changed: `agents/test_sync_reports.py` now checks
  `isinstance(hunter.ledger, VersionedFindingsLedger)` rather than the exact
  class name. The test's intent is "a real ledger, not a mock".

## Gaps / follow-ups

- **Bounty Core upstream:**
  - (a) Fail closed on an unparseable ledger (affects every existing writer).
  - (b) `_next_fid` should honor a persisted high-water mark, so the newest FID
    can be deleted.
  - (c) Move the tombstone guard into `_reserve_in_payload` /
    `_ledger_add_in_payload` / `add_finding`, so non-BBH callers are covered
    and the guard runs inside the same lock.
- **Guard race window:** the BBH guard reads tombstones just before the core insert
  takes the lock. A delete of exactly that identity, landing in that window,
  could still be re-added by a concurrent team run. Fix (c) closes this window.
- **Stale tombstone after a crash:** if the process dies after the tombstone
  append and before the ledger write, and the `delete_aborted` append also fails,
  the FID stays tombstoned while live. Updates to it are then skipped. Repair
  by appending a `restored` event by hand.
- LLM agents that hand-edit `ledger.json` bypass every code guard. That is
  prompt policy, not this change.
- Board UI wiring is not part of this branch. It can detect `--delete-finding`
  from `--help`, and should pass `--actor`.
