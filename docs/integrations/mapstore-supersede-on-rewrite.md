# MapStore supersede-on-rewrite integration dossier

- **Status:** review-ready (review loop 1 fixes applied)
- **Owner:** Hermes (delegated subagent)
- **Branch:** `fix/mapstore-update-in-place`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-mapstore-in-place`
- **Base commit:** `0821e438a24b1a161d90bd422b127ea42166d00c` (`origin/beta`); `origin/beta` `6f6ce2a9e1453a7aa600a0e3a36fa6f7ff7a6a30` merged into the branch as `22cba8e7`
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/mapstore-update-in-place`
- **Latest immutable recovery checkpoint:** recorded in the follow-up dossier-only commit (Git cannot embed a commit's own SHA)
- **Feature implementation commit(s):** `18529a2995be6fda138834fea651d302ebbf0d8a` (initial supersede); review-loop-1 fix commit recorded in the follow-up dossier-only commit
- **Inspiration / canonical references:** papercut `PC-20261006-184250-c75063f4` (HIGH, breaking); `bf777097` (append-safe URL observations), `f336512e` (reviewer attribution on updates), `ad546f6e` (retain orientation on behavior updates)

## Intent

A corrected re-write of the same MapStore fact created an identically tagged
sibling directory that stayed `active`, so a later agent could read the stale
fact (for example "surface unreachable" when it was live) as current. Workers
archived duplicates by hand.

Root cause: `MapStore.write()` had no identity notion. `_observation_dir()`
always picks a collision-free directory from `observation_slug(title, run_id)`
(`-2`, `-3` suffixes; a different `run_id` yields a different slug outright)
and never consults existing index rows. Tags never participated.

Unchanged boundaries: storage layout, existing statuses, append-safe (never
clobbered) files, `write` stdout (only the new path), the `update-status`
contract, and the existing lock.

## Implemented contract

- **Only explicitly titled writes supersede.** An untitled or blank-title write
  always adds a separate entry: its derived title (`surface/<urldir>` or
  `surface/<scope>`) cannot tell facts apart when the host or parameter lives
  only in the body.
- Identity of a titled observation = scope + slugified surface + normalized URL
  (trailing slash ignored, as in `query`) + title key + exact slugified tag set.
  The title key is Unicode-aware: casefolded with whitespace collapsed;
  punctuation stays significant (`a+b` and `a-b` are different facts; distinct
  non-ASCII titles are different facts). Run ID, agent, body, status, behaviors
  and crossfamily are not identity.
- Under the existing `.mapstore.lock`, `write` creates the new entry as before,
  then archives every non-archived same-identity entry whose file exists:
  `status: archived`, `superseded_by: <new path>`, a `status_history` record,
  `status_reason` naming the new path, the body `Status:` line and a
  `## Lifecycle Update` note. The prior file is kept verbatim as history.
- The reverse link `supersedes` is added to the new entry in the same index
  write that archives each old entry, so the two links never disagree.
- `_update_status_unlocked()` rewrites the observation file before the index:
  a failure leaves the index (which queries read) unchanged; an index-write
  failure after the file rewrite leaves the old file saying "archived,
  superseded by X" while the index still lists it active.
- **Archive-step failure (decision):** follows the existing URL Ingest
  projection convention. The new fact is already durable, so `write` catches
  `OSError`/`ValueError` per superseded entry, prints a `WARNING` naming both
  paths and the exact `update-status` recovery command, still prints the new
  path on stdout, and exits 0. Successful archives print one stderr line each.
- Pre-fix duplicate siblings collapse on the next same-identity titled write;
  archived entries are never re-archived or relinked.
- `query` text output shows `Supersedes:` on current entries and
  `Superseded by:` on archived ones; dedupe/coverage pointer lines append
  `| superseded by <path>`; `behavior show` displays `superseded_by`.
- `update_status()` delegates to `_update_status_unlocked()` so the write path
  can archive while holding the lock.

Non-claims: no fuzzy title matching (a reworded title is a distinct fact; the
reference tells agents to archive the old entry with `update-status` naming the
new path when a correction changes title or tags). Application Behavior
`observation_paths` and `hypothesis_ledger._public_lead` do not follow supersede
chains (recorded in `BUGFIXES.md`). No migration of existing real stores.

## Evidence and review

Python `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python`,
`PYTHONPATH=<bounty-core 5f5a66ac detached worktree>:<worktree>:<worktree>/agents`
(current BBH pin; the venv copy is older). Selection (9 files):
`agents/test_map_store.py agents/test_ai_review_attribution.py
agents/test_coverage_cli.py agents/test_leads_cli.py
agents/test_hypothesis_ledger.py agents/test_leads_skill.py
tests/test_skill_hygiene.py tests/test_data_store_guidance.py
tests/test_papercut_contract_docs.py`.

- Reproduction (synthetic store under the Hermes scratch dir): two CLI writes
  with the same URL/surface/title/tags from `run-a` then `run-b`. Base: two
  `active` rows. Branch: one `active` row (`run-b`, `supersedes: [run-a]`);
  `run-a` archived with the forward link and its original body intact.
- Review loop 1 regressions (untitled app/surface/URL facts with and without
  tags, blank title, distinct non-ASCII titles, punctuation-only titles,
  archive file/index failure, CLI output links) run against the reviewed tip
  `92782cf1` code: 10 of 12 fail as expected; the case/whitespace and
  same-non-ASCII-title supersede tests pass on both.
- Base `origin/beta` `6f6ce2a9`, 9-file selection: 127 passed.
- Branch working tree (identical to the review-fix commit), 9-file selection:
  144 passed
  (127 existing, 3 of them updated to the supersede contract, + 17 new).
- `git diff --check` clean; `skills/map-store/SKILL.md` stays at its 544-line
  budget.
- Independent review loop 1 (parent): BLOCK on untitled collapse plus nits;
  all addressed above. Re-review assigned to the parent.

## Blockers and deferred work

- **Existing duplicate siblings in real stores:** not touched. Titled ones
  collapse on the next same-identity write. A one-off cleanup is proposed, not
  run: for each program lane, group non-archived **titled** `map.jsonl` rows by
  the identity above, and for groups larger than one, archive all but the
  newest via `update-status` with reason `Superseded by <newest path> (pre-fix
  duplicate)`. Untitled rows cannot be grouped safely and need human review.
  Dry-run first, then review the list before any write.
- **Trigger:** operator approval of that cleanup.
- **Consumers not following supersede chains:** `BUGFIXES.md` entry; separate task.

## Interruption / resume handoff

- **Exact resume point:** parent re-review of the branch range, then a normal
  beta merge from a clean beta worktree.
- **Working-tree state at handoff:** clean.

## Decision gates

- **Integration gate:** independent re-review of `origin/beta..fix/mapstore-update-in-place`.
- **Activation gate:** beta runtime refresh (Hoster) is a separate decision.
- **Promotion gate:** normal beta-to-main promotion.

## Decision record

- 2026-11-24 — created; supersede chosen over in-place overwrite so existing
  `map:` Coverage pointers, URL Ingest receipts and Hypothesis pointers keep
  referencing the exact evidence they recorded, while only one entry stays
  current. Matches the manual worker workaround (archive with a reason).
- 2026-11-24 — implementation `18529a29` committed and pushed.
- 2026-11-24 — review loop 1 BLOCK (untitled writes collapsed distinct facts).
  Merged `origin/beta` `6f6ce2a9` (no rebase); supersede restricted to titled
  writes with a Unicode-aware, punctuation-significant title key; archive
  failures reported per entry without failing the write; file-before-index
  ordering; output links; docs corrected; consumer follow-up recorded in
  `BUGFIXES.md`.
