# Ledger Delete Finding — Integration Dossier

- **Branch:** `feat/ledger-delete-finding`
- **Base / target:** `origin/beta` `3f72ed81` / `beta` (after independent review)
- **Request (Ryushe):** "add a delete to the bbh ledger (so that way we can archive
  and from the archive we can delete items)". Follow-up: "archive -> delete
  deletes it; archive is how we can recover."

## Intent

Archive (`--edit-finding FID` with `{"status":"archive"}`) is the **only
recoverable state**. To recover an archived finding, change its status back.
`--delete-finding` is final:

- the record leaves the lane ledger;
- the finding's BBH-generated files are deleted;
- no copy of the finding is kept.

A minimal tombstone remains so that imports, team runs, and report syncs do not
quietly re-add the deleted finding. The same path cleans up schema-placeholder
findings.

## CLI contract

```text
bbh agents/manual_hunter.py <program> --family F --lane L [--root ROOT] --delete-finding FID [--actor LABEL]
```

`--delete-finding` is a mutually exclusive mode flag listed in `--help`, so the
Board can detect it there. There is no `--restore-finding`.

| Exit | Meaning |
|---|---|
| 0 | deleted |
| 1 | refused; nothing written. Message on stderr as `[manual_hunter] …` |
| 3 | deleted and committed, but a generated file could not be unlinked or the navigation/index refresh failed (`Warning:` on stderr) |
| 2 | argparse usage error |

Delete refuses when:

- the FID is unknown;
- the status is not `archive` (top-level `status`, lower-cased and stripped;
  `current.status` is used only when there is no top-level status);
- an import is pending on the finding;
- the ledger is malformed or not a regular file;
- the tombstone log is corrupt or a symlink;
- the FID is the **highest FID of its prefix** (see Decisions).

Output lines on success:

```text
Finding deleted: D07
Tombstone: <lane>/ledgers/deleted-findings.jsonl
Deleted file: <path>
Kept (<reason>): <path>
```

`Kept` reasons:

- `not BBH-generated`
- `generated report edited (checksum mismatch)`
- `evidence edited after creation`
- `symlink (not followed)`
- `outside lane or behind a symlink`
- `outside the lane reports root`
- `directory with non-generated content`
- `report_path not owned by this FID` / `finalized_report_path not owned by this FID`
- `packet pointer rejected: …`
- `changed during delete; left in place`
- `unlink failed: …`

### Tombstone (`ledgers/deleted-findings.jsonl`, mode 0600, append-only)

```json
{"schema":"bbh-deleted-finding/2","event":"deleted","fid":"D07",
 "identity_key":["<file>",<line>,"<class_name>","<type>"],
 "deleted_at":"2026-11-24T19:00:00Z","deleted_by":"<--actor or manual_hunter>"}
```

`identity_key` is Bounty Core's dedupe key (`_finding_key_for`: normalized file,
line, class, and lower-cased type). The resurrection guard needs it to match.
If a finding has no `type`, Bounty Core falls back to the title, so that
normalized label is kept. No description, evidence, report text, or ledger
paths are stored.

If the ledger write fails after the tombstone append, the delete appends
`{"event":"delete_aborted"}` and leaves every file untouched. The latest event
for a FID decides whether that FID is tombstoned.

## Decisions

- **Owner/writer.** The operation lives in `agents/ledger_tombstones.py`. It
  reuses Bounty Core's `_locked_payload` (`ledgers/ledger.lock` flock),
  `_write_json_atomic`, and payload migration, which is the same critical section
  `patch_finding_by_fid` uses. It does not add a parallel writer. Those helpers
  are private upstream; the natural long-term home is a Bounty Core
  `delete_finding_by_fid`.
- **Single critical section, unlink last.** Under one exclusive lock, the
  delete runs: validate the raw ledger and tombstone log → locate → status check
  → classify artifacts → append and fsync the tombstone → atomic ledger write →
  unlink generated files → prune an empty `_meta/` and packet directory →
  refresh `indexes/` and report navigation → write the ledger again.
  - Files are unlinked only after the ledger commit, because an unlink cannot be
    undone and must not happen if the ledger write fails.
  - Each file is re-checked immediately before it is unlinked: still a regular
    file, no symlinked path component, still generated or the untouched template.
  - The second ledger write is needed because the evidence-only refresh may fill
    packet pointers.
- **Fail closed.** Bounty Core reads an unparseable ledger as empty and writes
  that back. Delete parses the raw file under the lock first and raises before
  writing anything. The pre-existing writers still have this defect; it is
  recorded in `BUGFIXES.md`.
- **Which files are deleted.**
  - A `bounty-core-finding-report` whose `generated-checksum` matches:
    `REPORT.md`, `FINALIZED.md`, or a legacy `reports/findings/<bucket>/FID - *.md`.
    Candidates come from Bounty Core's own per-FID set (`_candidate_paths_for_fid`)
    plus the packet directory.
  - An `EVIDENCE.md` that is byte-identical to Bounty Core's create-only template
    for this record. The template is rendered in scratch storage with the real
    `ensure_finding_evidence_packet`, not a copied template.
  - Everything else is left in place and listed. Symlinks, including a symlinked
    packet directory, are never followed. Paths outside the lane are never touched.
- **Tombstone log fails closed.** A symlinked log, a non-file log, or any
  unreadable non-empty line raises `CorruptTombstoneLogError` from the guard and
  from delete. That blocks inserts in the lane until the log is repaired, rather
  than silently disabling the guard.
- **FID reuse.** Bounty Core's `_next_fid` allocates `max(suffix)+1` from the
  findings list alone. So the delete refuses the highest FID of its prefix,
  which keeps every deleted FID below the allocation high-water mark. The
  prefix is everything before the trailing digits.

## Resurrection paths and handling

| Path | Match | Handling |
|---|---|---|
| `manual_hunter --from-file/--add/--interactive/--watch` → `import_finding` | key (file, line, class, type) | Wrapper skips it. The CLI prints `Skipped: FID was permanently deleted from this lane` and exits 1, and never links a duplicate comment to a deleted FID. |
| `sync_reports` → `import_finding` (a leftover markdown `**FID:**` brings back the old FID) | FID or key | Wrapper skips it; the summary reports `Skipped: N deleted findings`, not "already exists". |
| `report_checker` / `base_team` promotion / `apk_deep_dive` / `zero_day_team` → `update_team_finding` fallback `ledger_add` (patch misses a deleted FID) | FID or key | Guarded before `ledger_add`. Returns `{"tombstoned": true}` and logs `[ledger] Skipped tombstoned finding …`. |
| Team sighting/reservation: `base_team.reserve_findings`, `apk_compat`, `zero_day_team`, `apk_deep_dive` → `ledger.check` | key | `TombstoneAwareFindingsLedger.check` (returned by `create_team_ledger`) reports a duplicate with `tombstoned=True`. |
| `reserve_batch`, `VersionedFindingsLedger.update` | key / FID | Guarded in the same wrapper (batch keeps result order). |
| `me_ledger.py add` → `ledger_add` | key | Refused with the skip message, exit 1. |
| `bounty_core.add_finding` / `ledger_add` called directly from outside BBH | identity / key | **Not guarded** (no BBH callers; needs Bounty Core). |
| `migrate_ledger_payload` FID assignment for FID-less rows | n/a | Not an insert; no change. |

When a candidate has no line and no type/title, the guard also matches on
(file, class), the same way Bounty Core's `import_finding`, `reserve_batch`, and
`ledger_check` match. A tombstoned identity is blocked exactly where Bounty Core
would have deduplicated it against the live finding. There is no override flag:
delete is final by design.

## Evidence

The interpreter is the shared BBH venv plus Bounty Core source at the
`requirements.txt` pin `9db8b23d`, via `PYTHONPATH`. The worktree has no `.venv`,
and offline install was impossible because a dependency was not in the uv cache.
`HOME` and `TMPDIR` pointed at scratch storage for every run.

- `tests/test_ledger_delete_finding.py` — **20 passed**. Coverage includes:
  - refusals: unarchived, unknown FID, highest FID, malformed ledger;
  - the minimal tombstone shape (exact keys, no finding text);
  - generated report and evidence deleted;
  - human-edited files, a symlink, a symlinked packet directory, and a foreign
    `report_path` kept;
  - a legacy lifecycle report deleted;
  - a lock wait and concurrent patches with no lost update;
  - a ledger-write failure aborting with no file touched;
  - manual, team (check/import/batch/update), `update_team_finding`,
    sync-style, file+class-only and `me_ledger` resurrection skips;
  - a corrupt or symlinked tombstone log failing closed;
  - no FID reuse;
  - `--help` lists `--delete-finding` and not `--restore-finding`.
- Relevant suites, the exact counts, and the branch-vs-base comparison are in
  the final handoff for this revision.
- `tests/skill_size_budget.json`: the `manual-hunter` budget goes from 136 to 140,
  for a 4-line pointer section.
- One existing assertion changed: `agents/test_sync_reports.py` now checks
  `isinstance(hunter.ledger, VersionedFindingsLedger)` rather than the exact
  class name. The test's intent is "a real ledger, not a mock".

## Gaps / follow-ups

- **Bounty Core upstream:**
  - (a) Fail closed on an unparseable ledger (affects every existing writer).
  - (b) `_next_fid` should honor a persisted high-water mark, so the newest FID
    can be deleted.
  - (c) Move the tombstone guard into `_reserve_in_payload` /
    `_ledger_add_in_payload` / `add_finding`, so non-BBH callers are covered and
    the guard runs inside the same lock.
- **Guard race window:** the BBH guard reads tombstones just before the core insert
  takes the lock. A delete of exactly that identity, landing in that window,
  could still be re-added by a concurrent team run.
- **Stale tombstone after a crash:** if the process dies after the tombstone
  append and before the ledger write, and the `delete_aborted` append also fails,
  the FID stays tombstoned while live. Repair by appending a `delete_aborted`
  event by hand.
- **No override for a genuine rediscovery:** a later, real finding with the
  exact same identity as a deleted one is skipped. This follows from "delete is
  final"; an override flag would need its own decision.
- LLM agents that hand-edit `ledger.json` bypass every code guard. That is
  prompt policy, not this change.
- Board UI wiring is not part of this branch. It can detect `--delete-finding`
  from `--help`, and should pass `--actor`.
