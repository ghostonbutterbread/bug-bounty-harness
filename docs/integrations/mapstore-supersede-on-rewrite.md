# MapStore supersede-on-rewrite integration dossier

- **Status:** review-ready
- **Owner:** Hermes (delegated subagent)
- **Branch:** `fix/mapstore-update-in-place`
- **Worktree:** `/home/ryushe/worktrees/bbh-fix-mapstore-in-place`
- **Base commit:** `0821e438a24b1a161d90bd422b127ea42166d00c` (`origin/beta`)
- **Intended integration target:** `beta`
- **Last updated:** 2026-11-24
- **Owning feature branch/ref:** `fix/mapstore-update-in-place`
- **Latest immutable recovery checkpoint:** `18529a2995be6fda138834fea651d302ebbf0d8a`
- **Feature implementation commit(s):** `18529a2995be6fda138834fea651d302ebbf0d8a`; the branch tip adds a later dossier-only receipt commit
- **Inspiration / canonical references:** papercut `PC-20261006-184250-c75063f4` (HIGH, breaking); `bf777097` (append-safe URL observations), `f336512e` (reviewer attribution on updates), `ad546f6e` (retain orientation on behavior updates)

## Intent

A corrected re-write of the same MapStore fact created an identically tagged
sibling directory that stayed `active`, so a later agent could read the stale
fact (for example "surface unreachable" when it was live) as current. Workers
archived duplicates by hand.

Root cause: `MapStore.write()` had no identity notion. `_observation_dir()`
always picks a collision-free directory from `observation_slug(title, run_id)`
(`-2`, `-3` suffixes; a different `run_id` yields a different slug outright)
and never consults existing index rows. Tags never participated. The
reviewer-merge lookup by path in `_write_observation_unlocked()` therefore never
matched an earlier write.

Unchanged boundaries: storage layout, existing statuses, append-safe (never
clobbered) files, `write` stdout (only the new path), the `update-status`
contract, and the existing lock.

## Implemented contract

- Identity of an observation = scope + slugified surface + normalized URL
  (trailing slash ignored, as in `query`) + slugified title (the stored title,
  including the derived title for untitled writes) + exact slugified tag set.
  Run ID, agent, body, status, behaviors and crossfamily are not identity.
- Under the existing `.mapstore.lock`, `write` creates the new entry as before,
  then archives every non-archived same-identity entry whose file exists:
  `status: archived`, `superseded_by: <new path>`, a `status_history` record,
  `status_reason` naming the new path, the body `Status:` line and a
  `## Lifecycle Update` note. The prior file is kept verbatim as history.
- The new entry lists `supersedes: [<old paths>]`. Default queries, pointer
  indexes and crossref views therefore show one current entry per identity.
- Pre-fix duplicate siblings collapse on the next same-identity write; archived
  entries are never re-archived or relinked.
- `write` emits one stderr line per superseded entry; `query` text output and
  `behavior show` display `superseded_by` so stale evidence links are navigable.
- `update_status()` now delegates to `_update_status_unlocked()` (pure
  extraction, same behavior) so the write path can archive while holding the lock.

Non-claims: no fuzzy title matching (a reworded title is a distinct fact);
Application Behavior `observation_paths` are not rewritten (they keep pointing
at the archived evidence, which now links forward); no migration of existing
real stores is performed.

## Evidence and review

Python `/home/ryushe/projects/bug_bounty_harness/.venv/bin/python`,
`PYTHONPATH=<bounty-core 9db8b23 detached worktree>:<worktree>:<worktree>/agents`
(the venv's bounty-core is 6c36ee88, behind the BBH pin).

- Reproduction (synthetic store under the Hermes scratch dir): two CLI writes
  with the same URL/surface/title/tags from `run-a` then `run-b`. Base: two
  `active` rows (`...-run-a/index.md`, `...-run-b/index.md`). Branch: one
  `active` row (`run-b`, `supersedes: [run-a]`); `run-a` archived with the
  forward link and its original body intact.
- Base `0821e438`, same 8-file selection
  (`agents/test_map_store.py agents/test_ai_review_attribution.py
  agents/test_coverage_cli.py agents/test_leads_cli.py
  agents/test_hypothesis_ledger.py agents/test_leads_skill.py
  tests/test_skill_hygiene.py tests/test_data_store_guidance.py`): 122 passed.
- New/updated tests run against base code: 7 of 8 fail as expected; the
  distinct-identity negative control passes on both.
- Branch `18529a29`, same 8 files plus `tests/test_papercut_contract_docs.py`:
  134 passed (122 existing + 7 new + 5 papercut-contract docs; 2 existing
  duplicate-title tests updated to the supersede contract). Skill-text suites
  that reference MapStore (17 files): 111 passed, 9 subtests passed.
  `git diff --check` clean; `skills/map-store/SKILL.md` stays at its 544-line
  budget.
- Independent review: not performed by the implementer; assigned to the parent.

## Blockers and deferred work

- **Existing duplicate siblings in real stores:** not touched. They collapse on
  the next same-identity write. A one-off cleanup is proposed, not run: for each
  program lane, group non-archived `map.jsonl` rows by the identity above, and
  for groups larger than one, archive all but the newest via `update-status`
  with reason `Superseded by <newest path> (pre-fix duplicate)`. Dry-run first,
  then review the list before any write.
- **Trigger:** operator approval of that cleanup.

## Interruption / resume handoff

- **Exact resume point:** independent review of the branch range, then a normal
  beta merge from a clean beta worktree.
- **Working-tree state at handoff:** clean.

## Decision gates

- **Integration gate:** independent review of `origin/beta..fix/mapstore-update-in-place`.
- **Activation gate:** beta runtime refresh (Hoster) is a separate decision.
- **Promotion gate:** normal beta-to-main promotion.

## Decision record

- 2026-11-24 — created; supersede chosen over in-place overwrite so existing
  `map:` Coverage pointers, URL Ingest receipts and Hypothesis pointers keep
  referencing the exact evidence they recorded, while only one entry stays
  current. Matches the manual worker workaround (archive with a reason).
- 2026-11-24 — implementation `18529a29` committed and pushed to
  `origin/fix/mapstore-update-in-place`; receipts recorded; review-ready.
