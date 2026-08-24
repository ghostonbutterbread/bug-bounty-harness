# Shared Skill Layout Adoption

## Status

Implemented; pending review and merge into `beta`.

## Ownership and Intent

BBH is the canonical owner of the `bounty-storage` and `huge-ingest` skills.
They were copied as source material from the general-skills layout worktree
without modifying that source worktree. This branch makes the BBH copies
discoverable through the registry, README, and runtime entry card.

## Branch Contract

- Worktree: `/home/ryushe/projects/bug_bounty_harness-shared-skill-layout`
- Feature branch: `feat/adopt-shared-skill-layout`
- Base: `f547c37bd7e12015537baf306d8bc7a05705b42a` (`origin/beta` at task start)
- Merge target: `beta`

## Implemented Contract

- `skills/bounty-storage/` owns storage-routing guidance and its two references.
- `skills/huge-ingest/` owns large-ingest guidance and its reference redirect.
- The adopted storage skill uses `$HARNESS_ROOT/SCRIPT_INDEX.md`, not a
  general-skills repository path.
- No BBH file hardcodes the general-skills source repository.

## Evidence

Run the focused adoption test and the existing registry/sync smoke checks before
merge. Inspect the staged diff and `git diff --check` before committing.

## Integration Boundary

After this commit and the corresponding general-skills layout commit are both
verified, remove the source skill directories from the general-skills repository
in the separately approved integration step. Do not remove them as part of this
BBH branch.
